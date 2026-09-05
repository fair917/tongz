// Command tongz runs the credential broker proxy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/fair917/tongz/internal/ca"
	"github.com/fair917/tongz/internal/config"
	"github.com/fair917/tongz/internal/install"
	"github.com/fair917/tongz/internal/proxy"
	"github.com/fair917/tongz/internal/secrets"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "tongz:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath = flag.String("config", "tongz.yaml", "path to the configuration file")
		listenAddr = flag.String("listen", "", "override the listen address from the configuration")
	)
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *listenAddr != "" {
		cfg.Listen = *listenAddr
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	store, err := secrets.Resolve(cfg.Secrets)
	if err != nil {
		return err
	}

	stateDir, err := expandUser(cfg.StateDir)
	if err != nil {
		return err
	}
	authority, err := ca.Load(stateDir)
	if err != nil {
		return err
	}
	authority.Prewarm(cfg.Hosts())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	store.StartRefresh(ctx, log)

	var auth string
	if cfg.ProxyAuth != "" {
		if auth, err = secrets.ResolveRef(cfg.ProxyAuth); err != nil {
			return fmt.Errorf("proxy_auth: %w", err)
		}
	}

	p := proxy.New(proxy.Options{
		Config:  cfg,
		CA:      authority,
		Secrets: store,
		Auth:    auth,
		Local: install.NewHandler(authority.CertPEM(), install.Options{
			GCPMetadata: cfg.MetadataRule() != nil,
		}),
		Log: log,
	})

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           p,
		ReadHeaderTimeout: 15 * time.Second,
	}

	announce(cfg, store, stateDir, auth != "")

	errc := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errc <- err
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}

// announce prints what the proxy will and will not do. Running in a weaker
// configuration than intended should be visible without reading the config.
func announce(cfg *config.Config, store *secrets.Store, stateDir string, authRequired bool) {
	fmt.Printf("tongz listening on %s\n", cfg.Listen)
	fmt.Printf("  CA               %s\n", filepath.Join(stateDir, "ca.pem"))
	fmt.Printf("  setup            curl -fsSL http://<gateway>:%s/install | sh\n", portOf(cfg.Listen))

	if authRequired {
		fmt.Println("  proxy auth       required")
	} else {
		fmt.Println("  proxy auth       DISABLED — any client that can reach this port may use it")
	}

	if host, _, err := net.SplitHostPort(cfg.Listen); err == nil {
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			fmt.Println("  WARNING          bound to loopback: containers cannot reach it, " +
				"while every process on this host can")
		}
	}

	for _, action := range []string{"inject", "sign", "respond"} {
		if hosts := hostsByAction(cfg, action); len(hosts) > 0 {
			fmt.Printf("  %-16s %s\n", label(action), strings.Join(hosts, ", "))
		}
	}
	if len(cfg.Passthrough) > 0 {
		names := make([]string, len(cfg.Passthrough))
		for i, p := range cfg.Passthrough {
			names[i] = string(p)
		}
		fmt.Printf("  tunnelling       %s (no credential can be injected)\n", strings.Join(names, ", "))
	}

	fmt.Printf("  credentials      %s\n", strings.Join(store.IDs(), ", "))
	fmt.Println("  everything else  tunnelled unmodified")
}

// hostsByAction lists the distinct hosts whose rules take the given action, so
// that the startup output says what happens to each rather than only that it is
// intercepted.
func hostsByAction(cfg *config.Config, action string) []string {
	seen := make(map[string]bool)
	var hosts []string
	for _, r := range cfg.Rules {
		if !strings.HasPrefix(r.Describe(), action) {
			continue
		}
		h := string(r.Match.Host)
		if !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	sort.Strings(hosts)
	return hosts
}

func label(action string) string {
	switch action {
	case "sign":
		return "signing"
	case "respond":
		return "answering"
	default:
		return "injecting"
	}
}

func portOf(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return port
	}
	return addr
}

func expandUser(path string) (string, error) {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("expand %q: %w", path, err)
	}
	return filepath.Join(home, strings.TrimPrefix(path, "~")), nil
}
