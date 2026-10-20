// Command lotor-development-connector exposes only a registered local bridge
// over an outbound connection. It does not contain Lotor's Control application.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/2kims/lotor-go/bridge"
	"github.com/2kims/lotor-go/bridge/development"
)

type configuration struct {
	ControlURL        string       `json:"control_url"`
	EndpointURL       string       `json:"endpoint_url"`
	ConnectionID      string       `json:"connection_id"`
	BindingID         string       `json:"binding_id"`
	SigningKeyID      string       `json:"signing_key_id"`
	SigningPrivateKey string       `json:"signing_private_key"`
	Scope             bridge.Scope `json:"scope"`
	LocalOrigin       string       `json:"local_origin"`
}

func main() {
	file := flag.String("config", "/run/lotor/development.json", "private connector configuration file")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, *file)
	cancel()
	if err != nil && !errors.Is(err, context.Canceled) {
		// Never print decoded configuration, credentials, proofs or upstream bodies.
		fmt.Fprintln(os.Stderr, "development connector could not run; check private configuration and bridge registration")
		os.Exit(1)
	}
}

func run(ctx context.Context, file string) error {
	info, err := os.Lstat(file)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 64<<10 {
		return bridge.ErrInvalid
	}
	opened, err := os.Open(file)
	if err != nil {
		return bridge.ErrInvalid
	}
	defer opened.Close()
	actual, err := opened.Stat()
	if err != nil || !os.SameFile(info, actual) || !actual.Mode().IsRegular() || actual.Mode().Perm()&0o077 != 0 {
		return bridge.ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(opened, (64<<10)+1))
	if err != nil || len(raw) > 64<<10 {
		clear(raw)
		return bridge.ErrInvalid
	}
	defer clear(raw)
	var config configuration
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || decoder.Decode(new(any)) != io.EOF {
		return bridge.ErrInvalid
	}
	private, err := base64.RawURLEncoding.Strict().DecodeString(config.SigningPrivateKey)
	if err != nil {
		return bridge.ErrInvalid
	}
	defer clear(private)
	if len(private) == ed25519.SeedSize {
		private = ed25519.NewKeyFromSeed(private)
		defer clear(private)
	}
	if len(private) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(private[:ed25519.SeedSize]), private) {
		return bridge.ErrInvalid
	}
	provider, err := development.NewProofSessionProvider(development.ProofSessionOptions{ControlURL: config.ControlURL, EndpointURL: config.EndpointURL, ConnectionID: config.ConnectionID, BindingID: config.BindingID, SigningKeyID: config.SigningKeyID, SigningKey: ed25519.PrivateKey(private), Scope: config.Scope})
	if err != nil {
		return err
	}
	handler, err := development.NewLocalHandler(config.LocalOrigin, nil)
	if err != nil {
		return err
	}
	ready := make(chan struct{}, 1)
	connector, err := development.NewConnector(development.ConnectorOptions{Session: provider, Handler: handler, Ready: ready})
	if err != nil {
		return err
	}
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ready:
				fmt.Fprintln(os.Stderr, "development bridge connected")
			}
		}
	}()
	return connector.Run(ctx)
}
