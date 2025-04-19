package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/sohelahmedjony/decentralize-wikileaks/internal/p2p"
)

const defaultPort = 4001 // Default listening port

func main() {
	fmt.Println("Decentralized Wikileaks Starting...")

	// Create a context that cancels on termination signals
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create the libp2p node
	host, err := p2p.CreateNode(ctx, defaultPort)
	if err != nil {
		log.Fatalf("Failed to create p2p node: %v", err)
	}
	defer func() {
		if err := host.Close(); err != nil {
			log.Printf("Error closing libp2p host: %v", err)
		}
	}()

	fmt.Printf("[*] Node started successfully (ID: %s)\n", host.ID().String())
	fmt.Println("[*] Waiting for connections. Press Ctrl+C to shut down.")

	// Wait for a termination signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\n[*] Received shutdown signal, closing node...")
	// Context cancellation and deferred host.Close() will handle shutdown
}
