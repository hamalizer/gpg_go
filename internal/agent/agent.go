// Package agent implements a passphrase caching daemon for gpg-go.
//
// The agent listens on a Unix domain socket and caches passphrases
// indexed by key fingerprint with a configurable TTL. This avoids
// repeated passphrase prompts during workflows like git commit signing.
package agent

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	DefaultTTL  = 10 * time.Minute
	SocketName  = "agent.sock"
	PIDFileName = "agent.pid"
)

// Request is sent from client to agent over the socket.
type Request struct {
	Action      string `json:"action"`      // "get", "put", "clear", "shutdown", "ping"
	Fingerprint string `json:"fingerprint"` // key fingerprint (for get/put)
	Passphrase  []byte `json:"passphrase"`  // passphrase bytes (for put)
	TTLSecs     int    `json:"ttl_secs"`    // optional per-entry TTL override
}

// Response is sent from agent to client.
type Response struct {
	OK         bool   `json:"ok"`
	Passphrase []byte `json:"passphrase,omitempty"`
	Message    string `json:"message,omitempty"`
}

type cacheEntry struct {
	passphrase []byte
	expires    time.Time
}

// Server is the passphrase caching agent.
type Server struct {
	mu       sync.Mutex
	cache    map[string]*cacheEntry
	ttl      time.Duration
	listener net.Listener
	homeDir  string
	done     chan struct{}
}

// NewServer creates a new agent server.
func NewServer(homeDir string, ttl time.Duration) *Server {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Server{
		cache:   make(map[string]*cacheEntry),
		ttl:     ttl,
		homeDir: homeDir,
		done:    make(chan struct{}),
	}
}

// SocketPath returns the path to the agent's Unix socket.
func SocketPath(homeDir string) string {
	return filepath.Join(homeDir, SocketName)
}

// PIDPath returns the path to the agent's PID file.
func PIDPath(homeDir string) string {
	return filepath.Join(homeDir, PIDFileName)
}

// Start begins listening and serving requests. Blocks until Shutdown is called.
func (s *Server) Start() error {
	sockPath := SocketPath(s.homeDir)

	// Clean up stale socket
	if _, err := os.Stat(sockPath); err == nil {
		os.Remove(sockPath)
	}

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.listener = ln

	// Restrict socket permissions
	if err := os.Chmod(sockPath, 0600); err != nil {
		ln.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}

	// Write PID file
	pidPath := PIDPath(s.homeDir)
	if err := os.WriteFile(pidPath, []byte(fmt.Sprintf("%d", os.Getpid())), 0600); err != nil {
		ln.Close()
		return fmt.Errorf("write pid: %w", err)
	}

	// Start cache expiry goroutine
	go s.reaper()

	// Accept connections
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return nil // clean shutdown
			default:
				continue
			}
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	var req Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		json.NewEncoder(conn).Encode(Response{OK: false, Message: "bad request"})
		return
	}

	var resp Response
	switch req.Action {
	case "ping":
		resp = Response{OK: true, Message: "pong"}

	case "get":
		s.mu.Lock()
		entry, ok := s.cache[req.Fingerprint]
		if ok && time.Now().Before(entry.expires) {
			// Copy passphrase so we don't hand out a reference to cached data
			pp := make([]byte, len(entry.passphrase))
			copy(pp, entry.passphrase)
			resp = Response{OK: true, Passphrase: pp}
		} else {
			if ok {
				// Expired, clean up
				zeroBytes(entry.passphrase)
				delete(s.cache, req.Fingerprint)
			}
			resp = Response{OK: false, Message: "not cached"}
		}
		s.mu.Unlock()

	case "put":
		ttl := s.ttl
		if req.TTLSecs > 0 {
			ttl = time.Duration(req.TTLSecs) * time.Second
		}
		pp := make([]byte, len(req.Passphrase))
		copy(pp, req.Passphrase)

		s.mu.Lock()
		// Zero old entry if it exists
		if old, ok := s.cache[req.Fingerprint]; ok {
			zeroBytes(old.passphrase)
		}
		s.cache[req.Fingerprint] = &cacheEntry{
			passphrase: pp,
			expires:    time.Now().Add(ttl),
		}
		s.mu.Unlock()
		resp = Response{OK: true, Message: "cached"}

	case "clear":
		s.mu.Lock()
		for fp, entry := range s.cache {
			zeroBytes(entry.passphrase)
			delete(s.cache, fp)
		}
		s.mu.Unlock()
		resp = Response{OK: true, Message: "cache cleared"}

	case "shutdown":
		resp = Response{OK: true, Message: "shutting down"}
		json.NewEncoder(conn).Encode(resp)
		s.Shutdown()
		return

	default:
		resp = Response{OK: false, Message: fmt.Sprintf("unknown action: %s", req.Action)}
	}

	json.NewEncoder(conn).Encode(resp)
}

// Shutdown stops the agent.
func (s *Server) Shutdown() {
	select {
	case <-s.done:
		return // already shutting down
	default:
	}
	close(s.done)

	if s.listener != nil {
		s.listener.Close()
	}

	// Zero all cached passphrases
	s.mu.Lock()
	for fp, entry := range s.cache {
		zeroBytes(entry.passphrase)
		delete(s.cache, fp)
	}
	s.mu.Unlock()

	// Clean up socket and PID file
	os.Remove(SocketPath(s.homeDir))
	os.Remove(PIDPath(s.homeDir))
}

// reaper periodically removes expired entries.
func (s *Server) reaper() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			now := time.Now()
			s.mu.Lock()
			for fp, entry := range s.cache {
				if now.After(entry.expires) {
					zeroBytes(entry.passphrase)
					delete(s.cache, fp)
				}
			}
			s.mu.Unlock()
		}
	}
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
