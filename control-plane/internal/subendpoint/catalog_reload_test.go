package subendpoint

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeCatalogFixture(t *testing.T, path, version, address string) {
	t.Helper()
	node := testCatalogNode()
	node.Address = address
	contents, err := json.Marshal(CatalogDocument{
		Version: version,
		Nodes:   []CatalogNode{node},
	})
	if err != nil {
		t.Fatalf("marshal catalog fixture: %v", err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write catalog fixture: %v", err)
	}
}

func renderedCatalogBody(
	t *testing.T,
	service *ReloadingCatalogSubscriptionService,
) string {
	t.Helper()
	result, err := service.BuildGeoRouted(
		context.Background(),
		&SubscriptionData{UserID: "subscriber"},
		"sing-box/1.11",
		"",
		"base64",
	)
	if err != nil {
		t.Fatalf("render catalog subscription: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(result.Body))
	if err != nil {
		t.Fatalf("decode catalog subscription: %v", err)
	}
	return string(decoded)
}

func TestCatalogReloadAtomicallyKeepsLastKnownGoodOnInvalidUpdate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")
	writeCatalogFixture(t, path, "v1", "203.0.113.42")

	service, err := NewReloadingCatalogSubscriptionService(path, DefaultCatalogReloadInterval)
	if err != nil {
		t.Fatalf("new reloading catalog service: %v", err)
	}
	if body := renderedCatalogBody(t, service); !strings.Contains(body, "203.0.113.42:443") {
		t.Fatalf("initial catalog endpoint missing: %q", body)
	}

	if err := os.WriteFile(path, []byte(`{"version":"v2","nodes":[`), 0o600); err != nil {
		t.Fatalf("write invalid replacement: %v", err)
	}
	result := service.Reload()
	if !result.Changed || result.Accepted || result.Err == nil {
		t.Fatalf("invalid replacement result = %+v, want changed rejected error", result)
	}
	if body := renderedCatalogBody(t, service); !strings.Contains(body, "203.0.113.42:443") {
		t.Fatalf("invalid replacement displaced last known-good catalog: %q", body)
	}
	status := service.Status()
	if status.ActiveVersion != "v1" || status.Rejected != 1 || status.LastError == "" {
		t.Fatalf("unexpected rejected reload status: %+v", status)
	}
}

func TestCatalogReloadAcceptsValidReplacementWithSameLengthAddress(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")
	writeCatalogFixture(t, path, "v1", "203.0.113.42")

	service, err := NewReloadingCatalogSubscriptionService(path, DefaultCatalogReloadInterval)
	if err != nil {
		t.Fatalf("new reloading catalog service: %v", err)
	}

	// The replacement address and version have the same lengths as v1, so this
	// proves the content digest—not only size or timestamp—drives a safe reload.
	writeCatalogFixture(t, path, "v2", "203.0.113.43")
	result := service.Reload()
	if !result.Changed || !result.Accepted || result.Err != nil {
		t.Fatalf("valid replacement result = %+v, want accepted change", result)
	}
	body := renderedCatalogBody(t, service)
	if !strings.Contains(body, "203.0.113.43:443") || strings.Contains(body, "203.0.113.42:443") {
		t.Fatalf("replacement catalog was not atomically served: %q", body)
	}
	status := service.Status()
	if status.ActiveVersion != "v2" || status.Accepted != 2 || status.LastError != "" {
		t.Fatalf("unexpected accepted reload status: %+v", status)
	}
}

func TestCatalogReloadRejectsSubSecondPollInterval(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")
	writeCatalogFixture(t, path, "v1", "203.0.113.42")
	if _, err := NewReloadingCatalogSubscriptionService(path, 500*time.Millisecond); err == nil {
		t.Fatal("sub-second catalog interval must be rejected")
	}
}

func TestCatalogReloadSkipsUnchangedContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")
	writeCatalogFixture(t, path, "v1", "203.0.113.42")

	service, err := NewReloadingCatalogSubscriptionService(path, DefaultCatalogReloadInterval)
	if err != nil {
		t.Fatalf("new reloading catalog service: %v", err)
	}
	result := service.Reload()
	if result.Changed || result.Accepted || result.Err != nil {
		t.Fatalf("unchanged reload result = %+v, want no-op", result)
	}
	if service.Status().Accepted != 1 {
		t.Fatalf("unchanged catalog must not increment accepted count: %+v", service.Status())
	}
}
