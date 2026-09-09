package portal

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testLoginFields(t *testing.T) url.Values {
	t.Helper()
	device, err := deviceDataJSON(DefaultUserAgent)
	if err != nil {
		t.Fatal(err)
	}
	return url.Values{fieldUserID: {"alice"}, fieldPassword: {"secret"}, fieldDeviceDetails: {device}, fieldWindowWidth: {"1470"}, fieldWindowHeight: {"956"}}
}

func TestDocumentPolicyRejectsBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); fmt.Fprint(w, "ok") }))
	defer srv.Close()
	c := newTestClient(t, srv)
	for _, path := range []string{
		"/banking-flatex.at/orderFormAction.do", "/banking-flatex.at/transferFormAction.do", "/banking-flatex.at/settingsFormAction.do",
		"/next-desktop.at/overviewFormAction.do?command=trade", "/banking-flatex.at/documentArchiveListFormAction.do?action=transfer",
		"/banking-flatex.at/downloadData/1/doc.pdf?action=transfer", "/banking-flatex.at/fetchCachedPage?windowId=W1&windowId=W2",
		"/banking-flatex.at/fetchCachedPage?windowId=W1;action=transfer", "/banking-flatex.at/downloadData/../orderFormAction.do",
		"/banking-flatex.at/downloadData/1/%2e%2e", "/banking-flatex.at/downloadData/1/%252e%252e", "/banking-flatex.at/downloadData/1/doc.pdf;command=trade",
		"/banking-flatex.at/downloadData/1%2ftrade/doc.pdf", "/banking-flatex.at/downloadData/1/doc%5c.pdf",
		"/banking-flatex/documentArchiveListFormAction.do", "/next-desktop.de/overviewFormAction.do",
	} {
		t.Run(path, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
			if response, err := c.hc.Do(req); err == nil {
				_ = response.Body.Close()
				t.Fatal("prohibited direct request accepted")
			}
		})
	}
	for _, method := range []string{"PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} {
		req, _ := http.NewRequest(method, srv.URL+c.archiveListPath, nil)
		if response, err := c.hc.Do(req); err == nil {
			_ = response.Body.Close()
			t.Errorf("accepted %s", method)
		}
	}
	for _, header := range []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override", "X-Original-URL", "X-Rewrite-URL"} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+c.loginPagePath, nil)
		req.Header.Set(header, "DELETE")
		if response, err := c.hc.Do(req); err == nil {
			_ = response.Body.Close()
			t.Errorf("accepted %s", header)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+c.loginPagePath, nil)
	req.Host = "evil.example"
	if response, err := c.hc.Do(req); err == nil {
		_ = response.Body.Close()
		t.Error("accepted Host override")
	}
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Header.Add("Content-Type", "application/json") },
		func(r *http.Request) { r.Trailer = http.Header{"X-Http-Method-Override": {"DELETE"}} },
		func(r *http.Request) { r.TransferEncoding = []string{"chunked"} },
		func(r *http.Request) { r.ContentLength++ },
	} {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+c.ssoPath, strings.NewReader(testLoginFields(t).Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		mutate(req)
		if response, err := c.hc.Do(req); err == nil {
			_ = response.Body.Close()
			t.Error("accepted ambiguous request framing or headers")
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("%d prohibited requests reached server", calls.Load())
	}
}

func TestDocumentPolicyRejectsUnsafeForms(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); fmt.Fprint(w, "ok") }))
	defer srv.Close()
	c := newTestClient(t, srv)
	archive := func() url.Values {
		f := archiveFilterForm(time.Now(), time.Now())
		f.Set(fieldApplyFilter, "true")
		return f
	}
	for _, field := range []string{"order.clicked", "transfer.clicked", "settings.clicked", "sessionPassword", "tan", "command", "_method"} {
		f := archive()
		f.Set(field, "true")
		if _, err := c.postFormOnce(c.archiveListPath, f); err == nil {
			t.Errorf("accepted %s", field)
		}
	}
	for _, value := range []string{"on", "true", "", "off&command=trade"} {
		f := archive()
		f.Set(fieldStoreSettings, value)
		if _, err := c.postFormOnce(c.archiveListPath, f); err == nil {
			t.Errorf("accepted storeSettings %q", value)
		}
	}
	f := archive()
	f.Add(fieldStoreSettings, "on")
	if _, err := c.postFormOnce(c.archiveListPath, f); err == nil {
		t.Error("accepted duplicate field")
	}
	for _, command := range []string{"trade", "transfer", "changeSettings", "resumeLogin"} {
		if _, err := c.postAjaxCommand(command, nil); err == nil {
			t.Errorf("accepted classical %s", command)
		}
	}
	for _, extra := range []url.Values{{fieldCommand: {cmdResumeLogin, "trade"}}, {fieldCommand: {cmdResumeLogin}, "tan": {"1234"}}} {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/next-desktop.at/ajaxCommandServlet", strings.NewReader(extra.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if response, err := c.hc.Do(req); err == nil {
			_ = response.Body.Close()
			t.Error("accepted unsafe Next command")
		}
	}
	for _, field := range []string{"order.clicked", "transfer.clicked", "settings.clicked"} {
		f := url.Values{fieldNextOverviewIdx: {"0"}, fieldNextOpenArchive: {"true"}, field: {"true"}}
		if _, err := c.postFormOnce("/next-desktop.at/overviewFormAction.do", f); err == nil {
			t.Errorf("accepted Next %s", field)
		}
	}
	f = testLoginFields(t)
	f.Set("sessionPassword", "true")
	if _, err := c.postFormOnce(c.ssoPath, f); err == nil {
		t.Error("accepted session authorization")
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, _ := mw.CreateFormFile(fieldUserID, "payload")
	_, _ = part.Write([]byte("alice"))
	_ = mw.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+c.ssoPath, &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if response, err := c.hc.Do(req); err == nil {
		_ = response.Body.Close()
		t.Error("accepted file part")
	}
	req, _ = http.NewRequest(http.MethodPost, srv.URL+c.ssoPath, strings.NewReader(strings.Repeat("x", 65537)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if response, err := c.hc.Do(req); err == nil {
		_ = response.Body.Close()
		t.Error("accepted oversized body")
	}
	if calls.Load() != 0 {
		t.Fatalf("%d prohibited requests reached server", calls.Load())
	}
}

func TestDocumentPolicyRejectsSameOriginRedirectActions(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, target := range []string{"/banking-flatex.at/orderFormAction.do", "/banking-flatex.at/transferFormAction.do", "/next-desktop.at/overviewFormAction.do", "/banking-flatex.at/ajaxCommandServlet?command=trade"} {
			t.Run(fmt.Sprintf("%d%s", status, target), func(t *testing.T) {
				var calls atomic.Int32
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.URL.Path == "/login.at/sso" {
						http.Redirect(w, r, target, status)
						return
					}
					t.Error("redirected operation reached server")
				}))
				defer srv.Close()
				c := newTestClient(t, srv)
				req, _ := http.NewRequest(http.MethodPost, srv.URL+c.ssoPath, strings.NewReader(testLoginFields(t).Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				// For 301/302/303, a plain overview GET is safe and intentional. Add
				// an action parameter so the redirect represents an actual operation.
				if target == "/next-desktop.at/overviewFormAction.do" && status < 307 {
					target += "?command=trade"
				}
				if response, err := c.hc.Do(req); err == nil {
					_ = response.Body.Close()
					t.Error("accepted redirected operation")
				}
				if calls.Load() != 1 {
					t.Errorf("outbound requests=%d, want only initial login", calls.Load())
				}
			})
		}
	}
}

// Exercise both GET and preserved-POST login redirects through net/http.
// The outer URL error reports the initial POST even if the blocked hop is GET.
func TestGermanClassicLoginHandoff(t *testing.T) {
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var handoffs int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.Method + " " + r.URL.Path {
				case "GET /login/loginIFrameFormAction.do":
					fmt.Fprint(w, `webcore.setTokenId("login-token");`)
				case "POST /login/sso":
					http.Redirect(w, r, "/banking-flatex/loginCommand?loginData=synthetic-token", status)
				case "GET /banking-flatex/loginCommand", "POST /banking-flatex/loginCommand":
					handoffs++
					if err := r.ParseForm(); err != nil {
						t.Error(err)
						return
					}
					if r.URL.Query().Get("loginData") != "synthetic-token" {
						t.Error("handoff lost login query")
					}
					if status == http.StatusTemporaryRedirect || status == http.StatusPermanentRedirect {
						if r.Method != "POST" || len(r.PostForm) != 5 || r.PostForm.Get("userId") != "test-user" || r.PostForm.Get("password") != "test-password" {
							t.Error("handoff lost original login fields")
						}
					} else if r.Method != "GET" || len(r.PostForm) != 0 || r.ContentLength != 0 {
						t.Error("GET handoff retained a login body")
					}
					http.SetCookie(w, &http.Cookie{Name: "flatexSession", Value: "test-session", Path: "/"})
					http.Redirect(w, r, "/banking-flatex/accountOverviewFormAction.do", http.StatusFound)
				case "GET /banking-flatex/accountOverviewFormAction.do":
					fmt.Fprint(w, `webcore.setTokenId("banking-token");`)
				case "POST /banking-flatex/ajaxCommandServlet":
					fmt.Fprint(w, `{"commands":[]}`)
				default:
					t.Errorf("unexpected route %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			c := newTestClient(t, srv, "flatex.de")
			if err := c.Login("test-user", "test-password"); err != nil {
				t.Fatal(err)
			}
			if handoffs != 1 {
				t.Fatalf("handoffs = %d, want 1", handoffs)
			}
		})
	}
}

func TestGermanClassicLoginHandoffRejectsOtherOperations(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, "unexpected")
	}))
	defer srv.Close()
	c := newTestClient(t, srv, "flatex.de")
	for _, tc := range []struct{ method, path, query string }{
		{"GET", "/banking-flatex/loginCommand", "loginData=synthetic"},
		{"PUT", "/banking-flatex/loginCommand", "loginData=synthetic"},
		{"POST", "/banking-flatex/loginCommand", ""},
		{"POST", "/banking-flatex/loginCommand", "loginData="},
		{"POST", "/banking-flatex/loginCommand", "loginData=one&loginData=two"},
		{"POST", "/banking-flatex/loginCommand", "loginData=synthetic&command=trade"},
		{"POST", "/banking-flatex/loginCommand", "loginData=synthetic%00"},
		{"POST", "/banking-flatex/loginCommand", "loginData=%zz"},
		{"POST", "/banking-flatex/orderFormAction.do", "loginData=synthetic"},
		{"POST", "/banking-flatex/transferFormAction.do", "loginData=synthetic"},
		{"POST", "/banking-flatex/settingsFormAction.do", "loginData=synthetic"},
		{"POST", "/login/sso", "loginData=synthetic"},
		{"POST", "/banking-flatex.at/loginCommand", "loginData=synthetic"},
		{"POST", "/next-desktop.de/loginCommand", "loginData=synthetic"},
	} {
		req, err := http.NewRequest(tc.method, srv.URL+tc.path+"?"+tc.query, strings.NewReader(testLoginFields(t).Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if response, err := c.hc.Do(req); err == nil {
			_ = response.Body.Close()
			t.Errorf("accepted %s %s?%s", tc.method, tc.path, tc.query)
		}
	}
	// Bodyless GET handoffs still reject malformed or extra query fields.
	for _, query := range []string{"", "loginData=", "loginData=one&loginData=two", "loginData=synthetic&command=trade", "loginData=synthetic%00", "loginData=%zz"} {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/banking-flatex/loginCommand?"+query, nil)
		if err != nil {
			t.Fatal(err)
		}
		if response, err := c.hc.Do(req); err == nil {
			_ = response.Body.Close()
			t.Errorf("accepted unsafe GET query %q", query)
		}
	}
	for _, field := range []string{"order.clicked", "transfer.clicked", "settings.clicked", "sessionPassword", "tan", "command", "_method", "loginData", "userId"} {
		f := testLoginFields(t)
		f.Add(field, "unsafe")
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/banking-flatex/loginCommand?loginData=synthetic", strings.NewReader(f.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if response, err := c.hc.Do(req); err == nil {
			_ = response.Body.Close()
			t.Errorf("accepted extra body field %s", field)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("%d prohibited requests reached server", calls.Load())
	}
}
