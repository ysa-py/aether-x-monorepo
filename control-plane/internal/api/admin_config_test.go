package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- GET /v1/transports ---

func TestTransportsCatalog(t *testing.T) {
	srv := &Server{Build: "admin-test"}

	req := httptest.NewRequest(http.MethodGet, "/v1/transports", nil)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp TransportsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Must contain every transport the subscriber/admin spec requires.
	have := map[string]bool{}
	for _, tr := range resp.Transports {
		have[tr.ID] = true
	}
	for _, id := range []string{"xhttp", "httpupgrade", "h2", "ws", "grpc", "kcp", "tcp", "quic"} {
		if !have[id] {
			t.Errorf("catalog missing transport %q", id)
		}
	}
	// Protocols present.
	pset := map[string]bool{}
	for _, p := range resp.Protocols {
		pset[p.ID] = true
	}
	if !pset["vless"] || !pset["trojan"] {
		t.Error("catalog missing protocols vless/trojan")
	}
}

// --- POST /v1/admin/build-config (happy path, every transport round-trips) ---

func TestBuildConfigAllTransports(t *testing.T) {
	for _, tr := range []string{"tcp", "kcp", "ws", "h2", "grpc", "httpupgrade", "xhttp", "quic"} {
		body := `{"protocol":"vless","transport":"` + tr + `","address":"node.example.com","port":443,"uuid":"uuid-1","path":"/sub","host":"front.example.com","sni":"front.example.com","service_name":"GunService","mode":"packet-up"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/admin/build-config", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		(&Server{Build: "t"}).Router().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("transport %q: status %d body %s", tr, rec.Code, rec.Body.String())
		}
		var resp BuildConfigResponse
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			t.Fatalf("transport %q decode: %v", tr, err)
		}
		if !strings.HasPrefix(resp.ShareLink, "vless://") {
			t.Errorf("transport %q: bad share link %s", tr, resp.ShareLink)
		}
		if !strings.Contains(resp.Clash, "network:") {
			t.Errorf("transport %q: clash missing network", tr)
		}
		if !strings.Contains(resp.Singbox, "outbounds") {
			t.Errorf("transport %q: singbox missing outbounds", tr)
		}
		// xhttp must reflect mode in the share link.
		if tr == "xhttp" && !strings.Contains(resp.ShareLink, "mode=packet-up") {
			t.Errorf("xhttp share link missing mode: %s", resp.ShareLink)
		}
		// grpc must carry serviceName.
		if tr == "grpc" && !strings.Contains(resp.ShareLink, "serviceName=GunService") {
			t.Errorf("grpc share link missing serviceName: %s", resp.ShareLink)
		}
	}
}

// --- Validation: bad protocol / transport rejected ---

func TestBuildConfigValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"bad protocol", `{"protocol":"bogus","transport":"ws","address":"h","port":443}`},
		{"bad transport", `{"protocol":"vless","transport":"bogus","address":"h","port":443}`},
		{"missing address", `{"protocol":"vless","transport":"ws","port":443}`},
		{"bad port", `{"protocol":"vless","transport":"ws","address":"h","port":0}`},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodPost, "/v1/admin/build-config", bytes.NewBufferString(c.body))
		rec := httptest.NewRecorder()
		(&Server{Build: "t"}).Router().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", c.name, rec.Code)
		}
	}
}

// --- malformed JSON ---

func TestBuildConfigBadJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/build-config", bytes.NewBufferString("{not json"))
	rec := httptest.NewRecorder()
	(&Server{Build: "t"}).Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestValidProtocolHelper(t *testing.T) {
	if !validProtocol("vless") {
		t.Error("vless should be valid")
	}
	if validProtocol("nope") {
		t.Error("nope should be invalid")
	}
}

// --- GET /v1/transport-profiles (Part 2 §5.2) ---

func TestTransportProfilesCatalog(t *testing.T) {
	srv := &Server{Build: "profiles-test"}
	req := httptest.NewRequest(http.MethodGet, "/v1/transport-profiles", nil)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp struct {
		Version  string `json:"version"`
		Profiles []struct {
			ID           string          `json:"id"`
			CoreKind     string          `json:"core_kind"`
			Network      string          `json:"network"`
			Security     string          `json:"security"`
			ConfigSchema json.RawMessage `json:"config_schema"`
			Newest       bool            `json:"newest"`
		} `json:"profiles"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Profiles) == 0 {
		t.Fatal("no profiles returned")
	}
	// Must include the explicitly-requested XHTTP profile for xray.
	haveXHTTP := false
	for _, p := range resp.Profiles {
		if p.CoreKind != "xray" && p.CoreKind != "sing-box" {
			t.Errorf("unknown core_kind %q", p.CoreKind)
		}
		if len(p.ConfigSchema) == 0 || !strings.HasPrefix(string(p.ConfigSchema), "{") {
			t.Errorf("profile %q has invalid config_schema", p.ID)
		}
		if p.CoreKind == "xray" && p.Network == "splithttp" {
			haveXHTTP = true
			if !p.Newest {
				t.Error("xhttp profile should be flagged newest")
			}
		}
	}
	if !haveXHTTP {
		t.Error("xray splithttp (XHTTP) profile missing")
	}
}
