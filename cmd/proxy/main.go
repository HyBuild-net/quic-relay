package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"quic-relay/internal/debug"
	"quic-relay/internal/handler"
	"quic-relay/internal/proxy"
)

func main() {
	configFlag := flag.String("config", "", "Config file path or JSON string")
	debugFlag := flag.Bool("d", false, "Enable debug logging")
	flag.Parse()

	if *debugFlag {
		debug.Enable()
	}

	if *configFlag == "" {
		log.Fatal("-config is required")
	}

	cfg, isFile, err := loadConfig(*configFlag)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Environment variables as fallback (config takes precedence)
	if cfg.Listen == "" {
		cfg.Listen = getEnv("QUIC_RELAY_LISTEN", ":5520")
	}

	chain, err := handler.BuildChain(cfg.Handlers)
	if err != nil {
		log.Fatalf("Failed to build handler chain: %v", err)
	}

	p := proxy.New(cfg.Listen, chain)
	p.SetSessionTimeout(cfg.SessionTimeout)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		for sig := range sigChan {
			switch sig {
			case syscall.SIGHUP:
				if !isFile {
					log.Println("[proxy] SIGHUP ignored (config is inline JSON, not a file)")
					continue
				}
				newCfg, _, err := loadConfig(*configFlag)
				if err != nil {
					log.Printf("[proxy] reload failed: %v", err)
					continue
				}
				newChain, err := handler.BuildChain(newCfg.Handlers)
				if err != nil {
					log.Printf("[proxy] reload failed: %v", err)
					continue
				}
				p.ReloadChain(newChain)
				p.SetSessionTimeout(newCfg.SessionTimeout)
				log.Printf("[proxy] config reloaded, handlers: %v, session_timeout: %ds", handlerNames(newChain), newCfg.SessionTimeout)
			case syscall.SIGINT, syscall.SIGTERM:
				log.Println("[proxy] shutting down...")
				p.Stop()
				return
			}
		}
	}()

	if err := p.Run(); err != nil {
		log.Fatalf("Proxy error: %v", err)
	}
}

// loadConfig loads config from a file path or parses inline JSON.
// Returns the config, whether it was loaded from a file, and any error.
func loadConfig(configFlag string) (*proxy.Config, bool, error) {
	if strings.HasPrefix(configFlag, "{") {
		cfg, err := proxy.ParseConfig([]byte(configFlag))
		return cfg, false, err
	}
	cfg, err := proxy.LoadConfig(configFlag)
	return cfg, true, err
}

// handlerNames returns the names of handlers in a chain.
func handlerNames(chain *handler.Chain) []string {
	var names []string
	for _, h := range chain.Handlers() {
		names = append(names, h.Name())
	}
	return names
}

// getEnv returns the environment variable value or a default.
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
