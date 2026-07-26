package clientengine

import (
	"os"
	"testing"
)

func TestDefaultClients(t *testing.T) {
	e := Default()
	if e.Count() == 0 {
		t.Fatal("expected builtin clients")
	}
}

func TestPlatformFilter(t *testing.T) {
	e := Default()
	iosClients := e.ClientsForPlatform("ios")
	if len(iosClients) == 0 {
		t.Fatal("expected iOS clients")
	}
}

func TestRenderURI(t *testing.T) {
	e := Default()
	rendered := e.RenderURI("test://{{SUB_URL_ENCODED}}&name={{REMARK}}", "https://sub.example.com/abc", "Test")
	if rendered == "" || rendered == "test://{{SUB_URL_ENCODED}}" {
		t.Fatal("template not substituted")
	}
}

func TestBase64Encode(t *testing.T) {
	if got := base64Encode("test"); got != "dGVzdA==" {
		t.Fatalf("got %s", got)
	}
}

func TestURLEncode(t *testing.T) {
	got := urlEncode("https://a.com/p?x=1")
	if got == "https://a.com/p?x=1" {
		t.Fatal("expected encoding")
	}
}

func TestLoadFromJSON(t *testing.T) {
	tmp := t.TempDir() + "/clients.json"
	os.WriteFile(tmp, []byte(`{"version":"2.0","clients":[{"name":"X","platform":"all","uri":"x://{{SUB_URL_ENCODED}}","icon":"x","priority":1}]}`), 0o644)
	e, err := New(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if e.Version() != "2.0" {
		t.Fatalf("version %s", e.Version())
	}
}
