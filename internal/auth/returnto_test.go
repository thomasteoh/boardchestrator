package auth

import "testing"

func TestSafeReturnTo(t *testing.T) {
	ok := []string{
		"/app",
		"/app/org/abc/settings",
		"/app/search?q=hello%20world",
		"/admin/identity-providers?x=1&y=%2Fz",
		"/a/b-c_d.e~f",
	}
	for _, in := range ok {
		if got := SafeReturnTo(in); got != in {
			t.Errorf("SafeReturnTo(%q) = %q, want it kept", in, got)
		}
	}
	bad := []string{
		"",
		"//evil.example",
		"//evil.example/app",
		"/\\evil.example",
		"\\\\evil.example",
		"/\\/evil.example",
		"https://evil.example",
		"http://evil.example/app",
		"HTTPS://evil.example",
		"javascript:alert(1)",
		"JaVaScRiPt:alert(1)",
		"data:text/html,x",
		"evil.example",
		"app",
		"/%2Fevil.example",
		"%2F%2Fevil.example",
		"/%5Cevil.example",
		"/%255Cevil.example",
		"%2f%2fevil.example",
		"/%2f%2fevil.example",
		"/\t/evil.example",
		"/\n/evil.example",
		"/%09/evil.example",
		"/%0d%0aSet-Cookie:x=y",
		"/app\r\nLocation: https://evil.example",
		"/app#frag",
		"/app%23frag",
		"/app\x00",
		"/%00",
		"/app/ ",
		"/%E2%80%A8",
		"/%zz",
		"/" + string(make([]byte, 2000)),
		"/%25252F%25252Fevil.example",
	}
	for _, in := range bad {
		if got := SafeReturnTo(in); got != DefaultReturnTo {
			t.Errorf("SafeReturnTo(%q) = %q, want %q", in, got, DefaultReturnTo)
		}
	}
}

func TestLoginURLFor(t *testing.T) {
	cases := map[string]string{
		"":                          "/login",
		"/app":                      "/login",
		"//evil.example":            "/login",
		"/admin/identity-providers": "/login?return_to=%2Fadmin%2Fidentity-providers",
	}
	for in, want := range cases {
		if got := LoginURLFor(in); got != want {
			t.Errorf("LoginURLFor(%q) = %q, want %q", in, got, want)
		}
	}
}
