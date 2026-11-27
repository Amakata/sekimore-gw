// The template runs on a real Unix socket, and its describe passes the gateway's checks.
//
// The describe rules below are a copy of check_describe in relay/src/forge/command.rs, kept to
// what a sidecar could get wrong; relay/tests/command_sidecar.rs runs this template through the
// gateway itself, so a drift between the copy and the gateway is caught there.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"unicode"
	"unicode/utf8"
)

const secret = "k-not-for-the-log"

// syncBuffer is the sidecar's log, written from the server's goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type running struct {
	path   string
	log    *syncBuffer
	client *http.Client
}

// socketDir is a short directory: t.TempDir() can pass the ~108 bytes a socket path may have.
func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func start(t *testing.T) *running {
	t.Helper()
	path := filepath.Join(socketDir(t), "notes.sock")
	ln, err := listen(path)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	srv := &http.Server{Handler: newSidecar(logs)}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}}
	return &running{path: path, log: logs, client: client}
}

func (r *running) request(t *testing.T, method, path string, body io.Reader) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, "http://sidecar"+path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("%s %s: Content-Type %q", method, path, ct)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("%s %s: the reply is not a JSON object: %v", method, path, err)
	}
	return resp.StatusCode, out
}

// command sends a command with the credential, or with credentials when they are given.
func (r *running) command(t *testing.T, name string, args any, credentials ...map[string]string) map[string]any {
	t.Helper()
	creds := map[string]string{"api_key": secret}
	if len(credentials) > 0 {
		creds = credentials[0]
	}
	body, _ := json.Marshal(map[string]any{
		"command":     name,
		"permission":  "",
		"project":     "case-template",
		"args":        args,
		"credentials": creds,
	})
	status, out := r.request(t, http.MethodPost, "/command", bytes.NewReader(body))
	if status != http.StatusOK {
		t.Fatalf("%s: HTTP %d %v", name, status, out)
	}
	return out
}

// errorOf is the error inside a 200 reply, or fails the test.
func errorOf(t *testing.T, out map[string]any) (int, string) {
	t.Helper()
	e, ok := out["error"].(map[string]any)
	if !ok {
		t.Fatalf("no error in %v", out)
	}
	return int(e["status"].(float64)), e["message"].(string)
}

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDescribeIsOneTheGatewayConnects(t *testing.T) {
	r := start(t)
	status, out := r.request(t, http.MethodGet, "/describe", nil)
	if status != http.StatusOK {
		t.Fatalf("HTTP %d", status)
	}
	if got := refusals(t, []byte(jsonOf(t, out)), "notes", []string{"notes"}); len(got) > 0 {
		t.Fatalf("the gateway would refuse it: %v", got)
	}
	perms := map[string]string{}
	for _, c := range out["commands"].([]any) {
		c := c.(map[string]any)
		perms[c["name"].(string)] = c["permission"].(string)
	}
	want := map[string]string{"note add": "notes:write", "note list": "notes:read"}
	if jsonOf(t, perms) != jsonOf(t, want) {
		t.Errorf("permissions %v, want %v", perms, want)
	}
	if out["about"] != "Short notes kept for this project" {
		t.Errorf("about %v", out["about"])
	}
}

func TestAddsANoteAndListsIt(t *testing.T) {
	r := start(t)
	empty := r.command(t, "note list", map[string]any{})
	if empty["message"] != "no notes" || jsonOf(t, empty["data"]) != "[]" {
		t.Errorf("an empty list: %v", empty)
	}
	added := r.command(t, "note add", map[string]any{"text": "hi", "tag": []string{"a", "b"}, "pin": true})
	if _, ok := added["error"]; ok {
		t.Fatalf("%v", added)
	}
	if got := jsonOf(t, added["data"]); got != `{"id":1,"pinned":true,"tags":["a","b"],"text":"hi"}` {
		t.Errorf("data %s", got)
	}
	if added["message"] != "added note 1" || jsonOf(t, added["calls"]) != "[]" {
		t.Errorf("%v", added)
	}
	second := r.command(t, "note add", map[string]any{"text": "second"})
	if got := jsonOf(t, second["data"]); got != `{"id":2,"pinned":false,"tags":[],"text":"second"}` {
		t.Errorf("defaults %s", got)
	}
	listed := r.command(t, "note list", map[string]any{"limit": 1})
	if listed["message"] != "2: second" || len(listed["data"].([]any)) != 1 {
		t.Errorf("limit 1: %v", listed)
	}
	all := r.command(t, "note list", nil)
	if all["message"] != "2: second\n1: hi" || jsonOf(t, all["calls"]) != "[]" {
		t.Errorf("newest first: %v", all)
	}
}

func TestAnswersAFailureInsideA200Reply(t *testing.T) {
	r := start(t)
	for _, creds := range []map[string]string{{}, {"api_key": ""}, {"other": "x"}} {
		status, msg := errorOf(t, r.command(t, "note list", nil, creds))
		if status != 503 || !strings.Contains(msg, "api_key") {
			t.Errorf("credentials %v: %d %q", creds, status, msg)
		}
	}
	// no credentials field at all
	status, out := r.request(t, http.MethodPost, "/command", strings.NewReader(`{"command": "note list"}`))
	if code, _ := errorOf(t, out); status != 200 || code != 503 {
		t.Errorf("no credentials: HTTP %d, %v", status, out)
	}
	for _, limit := range []int{0, -1} {
		status, msg := errorOf(t, r.command(t, "note list", map[string]any{"limit": limit}))
		if status != 400 || msg != "note list: --limit must be 1 or more" {
			t.Errorf("limit %d: %d %q", limit, status, msg)
		}
	}
	unknown := r.command(t, "note delete", nil)
	if status, msg := errorOf(t, unknown); status != 404 || !strings.Contains(msg, `"note delete"`) {
		t.Errorf("unknown command: %d %q", status, msg)
	}
	if jsonOf(t, unknown["calls"]) != "[]" {
		t.Errorf("calls %v", unknown["calls"])
	}
}

func TestAnswersWhatItDoesNotUnderstandWithAnHTTPError(t *testing.T) {
	r := start(t)
	cases := []struct {
		method, path string
		body         io.Reader
		status       int
		error        string
	}{
		{http.MethodGet, "/nothing", nil, 404, "no GET /nothing"},
		{http.MethodPost, "/describe", strings.NewReader("{}"), 404, "no POST /describe"},
		{http.MethodGet, "/command", nil, 404, "no GET /command"},
		{http.MethodPost, "/command", strings.NewReader("not json"), 400, "the body is not JSON"},
		{http.MethodPost, "/command", strings.NewReader("[1, 2]"), 400, "the body is not JSON"},
		{http.MethodPost, "/command", strings.NewReader(""), 400, "the body is not JSON"},
		// with a Content-Length over the cap: refused before it is read
		{http.MethodPost, "/command", bytes.NewReader(make([]byte, requestCap+1)), 413, "request too large"},
		// without one (chunked): refused once the cap is passed
		{http.MethodPost, "/command", io.MultiReader(bytes.NewReader(make([]byte, requestCap+1))), 413, "request too large"},
	}
	for _, c := range cases {
		status, out := r.request(t, c.method, c.path, c.body)
		if status != c.status || out["error"] != c.error {
			t.Errorf("%s %s: HTTP %d %v, want %d %q", c.method, c.path, status, out, c.status, c.error)
		}
	}
	// a body at the cap is read
	head := `{"command": "note list", "credentials": {"api_key": "x"}}`
	padded := head + strings.Repeat(" ", requestCap-len(head))
	status, out := r.request(t, http.MethodPost, "/command", strings.NewReader(padded))
	if status != 200 || out["message"] != "no notes" {
		t.Errorf("a body of exactly the cap: HTTP %d %v", status, out)
	}
}

func TestLogsTheRequestLineAndNeverABody(t *testing.T) {
	r := start(t)
	r.command(t, "note add", map[string]any{"text": "a private note"})
	r.request(t, http.MethodGet, "/describe", nil)
	logs := r.log.String()
	for _, want := range []string{"notes: POST /command HTTP/1.1\n", "notes: GET /describe HTTP/1.1\n"} {
		if !strings.Contains(logs, want) {
			t.Errorf("no %q in the log:\n%s", want, logs)
		}
	}
	for _, never := range []string{secret, "a private note"} {
		if strings.Contains(logs, never) {
			t.Errorf("%q is in the log:\n%s", never, logs)
		}
	}
}

func TestAddsConcurrentlyWithoutLosingANote(t *testing.T) {
	r := start(t)
	const n = 50
	ids := make(chan int, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// not r.command: t.Fatal may not be called from another goroutine
			body := fmt.Sprintf(`{"command": "note add", "args": {"text": "%d"}, "credentials": {"api_key": "x"}}`, i)
			resp, err := r.client.Post("http://sidecar/command", "application/json", strings.NewReader(body))
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			var out struct {
				Data note `json:"data"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
				t.Error(err)
				return
			}
			ids <- out.Data.ID
		}()
	}
	wg.Wait()
	close(ids)
	var got []int
	for id := range ids {
		got = append(got, id)
	}
	slices.Sort(got)
	for i, id := range got {
		if id != i+1 {
			t.Fatalf("ids %v: each note one id, 1 to %d", got, n)
		}
	}
	if listed := r.command(t, "note list", nil); len(listed["data"].([]any)) != n {
		t.Errorf("%d notes listed", len(listed["data"].([]any)))
	}
}

func TestListenReplacesAStaleSocketAndOpensItToTheGroup(t *testing.T) {
	dir := socketDir(t)
	path := filepath.Join(dir, "sub", "notes.sock") // a directory that is not there yet
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	// a socket a previous run left behind: bound, and closed without removing it
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	stale.Close()
	ln, err := listen(path)
	if err != nil {
		t.Fatalf("a stale socket: %v", err)
	}
	defer ln.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Type() != os.ModeSocket || info.Mode().Perm() != 0o660 {
		t.Errorf("mode %v, want a socket with 0660", info.Mode())
	}

	fresh := filepath.Join(dir, "new", "dir", "notes.sock")
	ln2, err := listen(fresh)
	if err != nil {
		t.Fatalf("a missing directory: %v", err)
	}
	ln2.Close()
}

// ---- A copy of the gateway's describe rules (relay/src/forge/command.rs check_describe) ----

const maxLine = 120

var (
	word             = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
	gatewayResources = []string{"ci", "issue", "pr", "project", "release", "repo", "search", "security"}
)

// unsafe is a control character or a bidirectional override (command.rs is_unsafe_char).
func unsafe(c rune) bool {
	return unicode.IsControl(c) || c == '؜' || c == '‎' || c == '‏' ||
		(c >= '‪' && c <= '‮') || (c >= '⁦' && c <= '⁩')
}

// badLine is a one-line text the gateway refuses: too long, a control character, or a bracket.
func badLine(text string) bool {
	return utf8.RuneCountInString(text) > maxLine || strings.ContainsFunc(text, unsafe) ||
		strings.ContainsAny(text, "[]")
}

type wireDescribe struct {
	Name      *string       `json:"name"`
	Version   *string       `json:"version"`
	Resources *[]string     `json:"resources"`
	About     string        `json:"about"`
	Guide     *string       `json:"guide"`
	Commands  []wireCommand `json:"commands"`
}

type wireCommand struct {
	Name       *string `json:"name"`
	About      *string `json:"about"`
	Permission *string `json:"permission"`
	Args       []struct {
		Name     *string `json:"name"`
		Help     string  `json:"help"`
		Kind     *string `json:"kind"`
		Required bool    `json:"required"`
	} `json:"args"`
}

// refusals is what the gateway would refuse in a describe; empty when it connects.
func refusals(t *testing.T, raw []byte, name string, declared []string) []string {
	t.Helper()
	var d wireDescribe
	if err := json.Unmarshal(raw, &d); err != nil {
		return []string{"unreadable: " + err.Error()}
	}
	if d.Name == nil || d.Version == nil || d.Resources == nil || d.Guide == nil {
		return []string{"name, version, resources and guide are required"}
	}
	var out []string
	if *d.Name != name {
		out = append(out, "names itself otherwise")
	}
	resources := *d.Resources
	for _, r := range resources {
		if !slices.Contains(declared, r) {
			out = append(out, "claims "+r)
		}
		if slices.Contains(gatewayResources, r) || !word.MatchString(r) {
			out = append(out, r+" is the gateway's")
		}
	}
	guide := *d.Guide
	if strings.TrimSpace(guide) == "" {
		out = append(out, "no guide")
	}
	if strings.ContainsFunc(guide, func(c rune) bool { return c != '\n' && c != '\t' && unsafe(c) }) {
		out = append(out, "a control character in the guide")
	}
	if badLine(d.About) {
		out = append(out, "about")
	}
	for _, part := range strings.Split(guide, "[")[1:] {
		inside, _, closed := strings.Cut(part, "]")
		r, a, perm := strings.Cut(inside, ":")
		if closed && perm && word.MatchString(r) && word.MatchString(a) && !slices.Contains(resources, r) {
			out = append(out, "guide names ["+inside+"]")
		}
	}
	var seen [][]string
	for _, c := range d.Commands {
		if c.Name == nil || c.About == nil || c.Permission == nil {
			out = append(out, "a command's name, about and permission are required")
			continue
		}
		words := strings.Fields(*c.Name)
		if len(words) < 1 || len(words) > 3 || !allWords(words) {
			out = append(out, *c.Name+": words")
		}
		for _, s := range seen {
			n := min(len(s), len(words))
			if slices.Equal(s[:n], words[:n]) {
				out = append(out, *c.Name+": overlaps")
			}
		}
		seen = append(seen, words)
		if badLine(*c.About) {
			out = append(out, *c.Name+": about")
		}
		r, a, _ := strings.Cut(*c.Permission, ":")
		if !slices.Contains(resources, r) || !word.MatchString(a) {
			out = append(out, *c.Name+": permission "+*c.Permission)
		}
		var names []string
		for _, arg := range c.Args {
			if arg.Name == nil {
				out = append(out, *c.Name+": an argument without a name")
				continue
			}
			if slices.Contains(names, *arg.Name) {
				out = append(out, *c.Name+": an argument twice")
			}
			names = append(names, *arg.Name)
			if !word.MatchString(*arg.Name) || *arg.Name == "help" {
				out = append(out, *c.Name+": argument "+*arg.Name)
			}
			kind := "string"
			if arg.Kind != nil {
				kind = *arg.Kind
			}
			if !slices.Contains([]string{"string", "int", "bool", "list"}, kind) {
				out = append(out, *c.Name+": kind "+kind)
			}
			if kind == "bool" && arg.Required {
				out = append(out, *c.Name+": a required flag")
			}
			if badLine(arg.Help) {
				out = append(out, *c.Name+": help of "+*arg.Name)
			}
		}
	}
	return out
}

func allWords(words []string) bool {
	for _, w := range words {
		if !word.MatchString(w) {
			return false
		}
	}
	return true
}

func TestTheCopyOfTheRulesRefusesWhatTheGatewayRefuses(t *testing.T) {
	base := `{"name": "notes", "version": "1", "resources": ["notes"], "guide": "[notes:write]",
		"commands": [{"name": "note add", "about": "x", "permission": "notes:write"}]}`
	declared := []string{"notes", "pr"}
	if got := refusals(t, []byte(base), "notes", declared); len(got) > 0 {
		t.Fatalf("the base is refused: %v", got)
	}
	cmd := func(fields string) string {
		return `{"commands": [{"name": "note add", "about": "x", "permission": "notes:write"` + fields + `}]}`
	}
	for _, change := range []string{
		`{"name": "memo"}`,
		`{"version": null}`,
		`{"guide": " "}`,
		`{"guide": "merge with [pr:merge]"}`,
		`{"guide": "[notes:write]\u001b[2J"}`,
		`{"about": "Notes\nhelp  Print this message"}`,
		`{"about": "Notes [not available: x]"}`,
		`{"about": "` + strings.Repeat("x", 121) + `"}`,
		`{"resources": ["notes", "pr"]}`,
		`{"resources": ["notes", "s3"]}`,
		`{"commands": [{"name": "note", "about": "x", "permission": "notes:write"},
			{"name": "note add", "about": "x", "permission": "notes:write"}]}`,
		`{"commands": [{"name": "Note", "about": "x", "permission": "notes:write"}]}`,
		`{"commands": [{"name": "note add", "permission": "notes:write"}]}`,
		`{"commands": [{"name": "a b c d", "about": "x", "permission": "notes:write"}]}`,
		`{"commands": [{"name": "note add", "about": "x", "permission": "pr:merge"}]}`,
		`{"commands": [{"name": "note add", "about": "x", "permission": "notes"}]}`,
		`{"commands": [{"name": "note add", "about": "x\u001b[2J", "permission": "notes:write"}]}`,
		cmd(`, "args": [{"name": "text", "help": "a‮b"}]`),
		cmd(`, "args": [{"name": "pin", "kind": "bool", "required": true}]`),
		cmd(`, "args": [{"name": "help"}]`),
		cmd(`, "args": [{"name": "Text"}]`),
		cmd(`, "args": [{"name": "text"}, {"name": "text"}]`),
		cmd(`, "args": [{"name": "n", "kind": "float"}]`),
	} {
		merged := map[string]any{}
		for _, part := range []string{base, change} {
			var m map[string]any
			if err := json.Unmarshal([]byte(part), &m); err != nil {
				t.Fatalf("%s: %v", part, err)
			}
			for k, v := range m {
				merged[k] = v
			}
		}
		if got := refusals(t, []byte(jsonOf(t, merged)), "notes", declared); len(got) == 0 {
			t.Errorf("not refused: %s", change)
		}
	}
}

func TestListenRefusesAPathItCannotBind(t *testing.T) {
	blocker := filepath.Join(socketDir(t), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if ln, err := listen(filepath.Join(blocker, "notes.sock")); err == nil {
		ln.Close()
		t.Error("listened under a regular file")
	}
}
