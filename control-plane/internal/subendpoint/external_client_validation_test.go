package subendpoint

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// These are deliberately pinned release assets, not "latest" URLs. The
// expected digests are GitHub release-asset SHA-256 digests retrieved when this
// test was added. Updating a client version requires a reviewable PR which
// updates both the version URL and digest.
const (
	singBoxVersion = "1.13.14"
	singBoxURL     = "https://github.com/SagerNet/sing-box/releases/download/v1.13.14/sing-box-1.13.14-linux-amd64.tar.gz"
	singBoxSHA256  = "f48703461a15476951ac4967cdad339d986f4b8096b4eb3ff0829a500502d697"

	mihomoVersion = "1.19.29"
	mihomoURL     = "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.29/mihomo-linux-amd64-compatible-v1.19.29.gz"
	mihomoSHA256  = "5612e698e96c8b8ad15abc4c0a4f098eba9234354b4f248cb97f2528e215b094"
)

// TestExternalClientParsersAcceptGeneratedSubscriptionConfigs is intentionally
// enabled only in CI. It downloads two pinned upstream parser binaries, verifies
// their release-asset SHA-256 values, and feeds them bytes produced directly by
// BuildSubscriptionBodyEx / BuildProxyLink in config_builder.go. A local
// developer sees an explicit skip rather than a hidden pass when the upstream
// client binaries are unavailable.
func TestExternalClientParsersAcceptGeneratedSubscriptionConfigs(t *testing.T) {
	if os.Getenv("CI") != "true" {
		t.Skip("external client parser validation runs in CI only; it downloads pinned upstream binaries")
	}

	fixture := externalParserFixture()
	singboxBody, contentType := BuildSubscriptionBodyEx([]ProxyLinkConfig{fixture}, "singbox")
	if contentType != "application/json; charset=utf-8" {
		t.Fatalf("sing-box content type = %q", contentType)
	}
	mihomoBody, contentType := BuildSubscriptionBodyEx([]ProxyLinkConfig{fixture}, "clash")
	if contentType != "text/yaml; charset=utf-8" {
		t.Fatalf("mihomo content type = %q", contentType)
	}
	vlessURI := BuildProxyLink(fixture)
	validateVLESSURI(t, vlessURI, fixture)

	dir := t.TempDir()
	singboxConfig := filepath.Join(dir, "generated-sing-box.json")
	mihomoConfig := filepath.Join(dir, "generated-mihomo.yaml")
	if err := os.WriteFile(singboxConfig, singboxBody, 0o600); err != nil {
		t.Fatalf("write generated sing-box config: %v", err)
	}
	if err := os.WriteFile(mihomoConfig, mihomoBody, 0o600); err != nil {
		t.Fatalf("write generated mihomo config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	singbox := downloadTarGzBinary(ctx, t, dir, singBoxURL, singBoxSHA256, "sing-box")
	mihomo := downloadGzipBinary(ctx, t, dir, mihomoURL, mihomoSHA256, "mihomo")

	runClientValidator(t, ctx, singbox, "check", "-c", singboxConfig)
	runClientValidator(t, ctx, mihomo, "-t", "-f", mihomoConfig)
}

func externalParserFixture() ProxyLinkConfig {
	return ProxyLinkConfig{
		UserID:   "external-client-ci",
		Remark:   "Aether-X external-client CI",
		FragPath: "external-ci",
		Node: NodeConfig{
			ID:         "external-client-ci-node",
			Address:    "198.51.100.42",
			Port:       443,
			Protocol:   "vless",
			UUID:       "123e4567-e89b-42d3-a456-426614174000",
			Encryption: "none",
			Transport:  "ws",
			Path:       "/external-client-ci",
			Host:       "front.external-client.invalid",
			SNI:        "front.external-client.invalid",
			ALPN:       "http/1.1",
		},
	}
}

// validateVLESSURI is a structural xray-family check. xray-core exposes native
// JSON config validation but no CLI which imports a VLESS subscription URI, so
// this is deliberately reported as URI-structure validation, not xray-core
// runtime acceptance.
func validateVLESSURI(t *testing.T, raw string, fixture ProxyLinkConfig) {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse generated VLESS URI: %v", err)
	}
	if parsed.Scheme != "vless" {
		t.Fatalf("scheme = %q, want vless", parsed.Scheme)
	}
	if parsed.User == nil {
		t.Fatal("VLESS URI lacks userinfo UUID")
	}
	if _, err := uuid.Parse(parsed.User.Username()); err != nil {
		t.Fatalf("VLESS URI UUID %q is invalid: %v", parsed.User.Username(), err)
	}
	if parsed.Hostname() != fixture.Node.Address || parsed.Port() != "443" {
		t.Fatalf("VLESS endpoint = %q, want %s:443", parsed.Host, fixture.Node.Address)
	}
	query := parsed.Query()
	for key, want := range map[string]string{
		"encryption": "none",
		"security":   "tls",
		"type":       "ws",
		"path":       fixture.Node.Path,
		"host":       fixture.Node.Host,
		"sni":        fixture.Node.SNI,
		"alpn":       fixture.Node.ALPN,
	} {
		if got := query.Get(key); got != want {
			t.Fatalf("VLESS URI query %s = %q, want %q", key, got, want)
		}
	}
	if parsed.Fragment == "" {
		t.Fatal("VLESS URI lacks a fragment/remark")
	}
}

func runClientValidator(t *testing.T, ctx context.Context, binary string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, binary, args...)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("%s %s timed out: %v", filepath.Base(binary), strings.Join(args, " "), ctx.Err())
	}
	if err != nil {
		t.Fatalf(
			"%s %s rejected config: %v\n%s",
			filepath.Base(binary),
			strings.Join(args, " "),
			err,
			output,
		)
	}
}

func downloadTarGzBinary(
	ctx context.Context,
	t *testing.T,
	directory, assetURL, expectedSHA256, binaryName string,
) string {
	t.Helper()
	archive := downloadAndVerify(t, ctx, directory, assetURL, expectedSHA256)
	file, err := os.Open(archive)
	if err != nil {
		t.Fatalf("open %s archive: %v", binaryName, err)
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatalf("open %s gzip archive: %v", binaryName, err)
	}
	defer reader.Close()

	tarReader := tar.NewReader(reader)
	destination := filepath.Join(directory, binaryName)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read %s tar archive: %v", binaryName, err)
		}
		if header.Typeflag != tar.TypeReg || path.Base(header.Name) != binaryName {
			continue
		}
		out, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o700)
		if err != nil {
			t.Fatalf("create %s binary: %v", binaryName, err)
		}
		_, copyErr := io.Copy(out, tarReader)
		closeErr := out.Close()
		if copyErr != nil || closeErr != nil {
			t.Fatalf("extract %s binary: copy=%v close=%v", binaryName, copyErr, closeErr)
		}
		return destination
	}
	t.Fatalf("%s binary not found in release archive", binaryName)
	return ""
}

func downloadGzipBinary(
	ctx context.Context,
	t *testing.T,
	directory, assetURL, expectedSHA256, binaryName string,
) string {
	t.Helper()
	archive := downloadAndVerify(t, ctx, directory, assetURL, expectedSHA256)
	file, err := os.Open(archive)
	if err != nil {
		t.Fatalf("open %s archive: %v", binaryName, err)
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatalf("open %s gzip asset: %v", binaryName, err)
	}
	defer reader.Close()

	destination := filepath.Join(directory, binaryName)
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o700)
	if err != nil {
		t.Fatalf("create %s binary: %v", binaryName, err)
	}
	_, copyErr := io.Copy(out, reader)
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatalf("extract %s binary: copy=%v close=%v", binaryName, copyErr, closeErr)
	}
	return destination
}

func downloadAndVerify(
	t *testing.T,
	ctx context.Context,
	directory, assetURL, expectedSHA256 string,
) string {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, assetURL, nil)
	if err != nil {
		t.Fatalf("create release asset request: %v", err)
	}
	response, err := (&http.Client{Timeout: 2 * time.Minute}).Do(request)
	if err != nil {
		t.Fatalf("download %s: %v", assetURL, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("download %s: HTTP %s", assetURL, response.Status)
	}

	assetPath := filepath.Join(directory, fmt.Sprintf("asset-%x", sha256.Sum256([]byte(assetURL))))
	asset, err := os.OpenFile(assetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("create downloaded asset: %v", err)
	}
	hash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(asset, hash), response.Body)
	closeErr := asset.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatalf("save %s: copy=%v close=%v", assetURL, copyErr, closeErr)
	}
	if got := hex.EncodeToString(hash.Sum(nil)); !strings.EqualFold(got, expectedSHA256) {
		t.Fatalf("SHA-256 for %s = %s, want %s", assetURL, got, expectedSHA256)
	}
	return assetPath
}
