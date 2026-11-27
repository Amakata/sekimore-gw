// Command notes is a minimal command sidecar for sekimore-gw: in-memory notes.
//
// Go standard library only. The protocol is docs/sidecar-protocol.md.
//
//	go run . --socket /run/sekimore-sidecars/notes.sock
//
// The gateway has already checked the permission and the arguments of every call that reaches
// POST /command. This file decides nothing, stores no credential and writes no audit.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	name       = "notes" // must equal the key under relay.sidecars in config.yml
	version    = "0.1.0"
	requestCap = 8 << 20 // the largest request this sidecar reads (8 MiB)
)

// What GET /describe answers. The gateway holds it to config.yml and to the rules in
// docs/sidecar-protocol.md ("What the gateway checks").
type describe struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Resources []string  `json:"resources"`
	About     string    `json:"about,omitempty"`
	Guide     string    `json:"guide"`
	Commands  []command `json:"commands"`
}

type command struct {
	Name       string `json:"name"`
	About      string `json:"about"`
	Permission string `json:"permission"`
	Args       []arg  `json:"args,omitempty"`
}

type arg struct {
	Name     string `json:"name"`
	Help     string `json:"help,omitempty"`
	Kind     string `json:"kind,omitempty"` // string (the default), int, bool, list
	Required bool   `json:"required,omitempty"`
}

var description = describe{
	Name:      name,
	Version:   version,
	Resources: []string{"notes"},
	// optional: the sidecar's line in `sgw-agent --help`; one line, no [ ], 120 characters at most
	About: "Short notes kept for this project",
	Guide: "## notes\n\n" +
		"Short notes kept by the notes sidecar for this project.\n\n" +
		"- `sgw-agent notes note add --text <text> [--tag <tag>]... [--pin]` adds a note [notes:write]\n" +
		"- `sgw-agent notes note list [--limit <n>]` lists the notes, newest first [notes:read]\n",
	Commands: []command{
		{
			Name:       "note add",
			About:      "Add a note",
			Permission: "notes:write",
			Args: []arg{
				{Name: "text", Help: "The note", Kind: "string", Required: true},
				{Name: "tag", Help: "A tag; repeat for more", Kind: "list"},
				{Name: "pin", Help: "Pin the note", Kind: "bool"},
			},
		},
		{
			Name:       "note list",
			About:      "List the notes, newest first",
			Permission: "notes:read",
			Args:       []arg{{Name: "limit", Help: "At most this many", Kind: "int"}},
		},
	},
}

// The body of POST /command. Everything in it has been checked by the gateway.
type commandRequest struct {
	Command     string            `json:"command"`
	Permission  string            `json:"permission"`
	Project     string            `json:"project"`
	Args        json.RawMessage   `json:"args"`
	Credentials map[string]string `json:"credentials"`
}

// The reply to POST /command. A failure is an error inside a 200 reply: a non-2xx HTTP status
// means "the sidecar is broken".
type reply struct {
	Message string     `json:"message,omitempty"`
	Data    any        `json:"data,omitempty"`
	Error   *wireError `json:"error,omitempty"`
	// Every upstream call made for this command, for the gateway's audit:
	// {"method": "POST", "path": "/v1/notes", "status": 201}. This example makes none.
	Calls []call `json:"calls"`
}

type wireError struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

type call struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
}

type note struct {
	ID     int      `json:"id"`
	Text   string   `json:"text"`
	Tags   []string `json:"tags"`
	Pinned bool     `json:"pinned"`
}

func failure(status int, message string) reply {
	return reply{Error: &wireError{Status: status, Message: message}}
}

// sidecar serves the protocol. Its notes are lost on restart: a sidecar keeps nothing it cannot
// afford to lose. Requests are served concurrently, so the notes are behind a lock.
type sidecar struct {
	mu    sync.Mutex
	notes []note
	log   *log.Logger
}

func newSidecar(logTo io.Writer) *sidecar {
	return &sidecar{log: log.New(logTo, name+": ", 0)}
}

func (s *sidecar) noteAdd(raw json.RawMessage) reply {
	var a struct {
		Text string   `json:"text"`
		Tag  []string `json:"tag"`
		Pin  bool     `json:"pin"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return failure(http.StatusBadRequest, "note add: "+err.Error())
	}
	n := note{Text: a.Text, Tags: a.Tag, Pinned: a.Pin}
	if n.Tags == nil {
		n.Tags = []string{}
	}
	s.mu.Lock()
	n.ID = len(s.notes) + 1
	s.notes = append(s.notes, n)
	s.mu.Unlock()
	return reply{Message: fmt.Sprintf("added note %d", n.ID), Data: n}
}

func (s *sidecar) noteList(raw json.RawMessage) reply {
	var a struct {
		Limit *int `json:"limit"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return failure(http.StatusBadRequest, "note list: "+err.Error())
	}
	if a.Limit != nil && *a.Limit < 1 {
		return failure(http.StatusBadRequest, "note list: --limit must be 1 or more")
	}
	s.mu.Lock()
	out := make([]note, 0, len(s.notes))
	for i := len(s.notes) - 1; i >= 0 && (a.Limit == nil || len(out) < *a.Limit); i-- {
		out = append(out, s.notes[i])
	}
	s.mu.Unlock()
	lines := make([]string, 0, len(out))
	for _, n := range out {
		lines = append(lines, fmt.Sprintf("%d: %s", n.ID, n.Text))
	}
	if len(lines) == 0 {
		lines = []string{"no notes"}
	}
	return reply{Message: strings.Join(lines, "\n"), Data: out}
}

// decodeArgs reads a command's arguments; absent or null is no arguments.
func decodeArgs(raw json.RawMessage, into any) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return json.Unmarshal(raw, into)
}

func (s *sidecar) command(req commandRequest) reply {
	// Read the credential where it is used, and never put it in a reply or a log line.
	// A real sidecar would send it to its service here, through the gateway's 443 passthrough.
	if req.Credentials["api_key"] == "" {
		return failure(http.StatusServiceUnavailable,
			"the notes sidecar was sent no api_key; set relay.sidecars.notes.credentials")
	}
	var r reply
	switch req.Command {
	case "note add":
		r = s.noteAdd(req.Args)
	case "note list":
		r = s.noteList(req.Args)
	default:
		r = failure(http.StatusNotFound, fmt.Sprintf("no command %q", req.Command))
	}
	r.Calls = []call{}
	return r
}

func (s *sidecar) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The request line only: never a body, which carries the credentials.
	s.log.Printf("%s %s %s", r.Method, r.URL.RequestURI(), r.Proto)
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/describe":
		writeJSON(w, http.StatusOK, description)
	case r.Method == http.MethodPost && r.URL.Path == "/command":
		if r.ContentLength > requestCap {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request too large"})
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, requestCap))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request too large"})
			} else {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "the body could not be read"})
			}
			return
		}
		var req commandRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "the body is not JSON"})
			return
		}
		writeJSON(w, http.StatusOK, s.command(req))
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("no %s %s", r.Method, r.URL.Path)})
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(body) // the replies are plain structs and strings: encoding them cannot fail
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprint(buf.Len()))
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// listen binds the socket, replacing one a previous run left behind; only the gateway connects.
func listen(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func main() {
	socket := flag.String("socket", "", "where to listen (on the shared volume)")
	flag.Parse()
	if *socket == "" {
		fmt.Fprintln(os.Stderr, name+": --socket is required")
		flag.Usage()
		os.Exit(2)
	}
	ln, err := listen(*socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
		os.Exit(1)
	}
	srv := &http.Server{Handler: newSidecar(os.Stderr), ReadHeaderTimeout: 10 * time.Second}
	// Stop at once on `docker stop` (and so on `sgw recreate`): as PID 1, a process that does not
	// handle SIGTERM is left running until the runtime kills it.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown) // lets the calls in flight finish, and removes the socket
	}()
	fmt.Fprintf(os.Stderr, "%s %s listening\n", name, version)
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
		os.Exit(1)
	}
	<-done
}
