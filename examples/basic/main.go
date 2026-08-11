// Command basic demonstrates verified owner discovery and one authorization
// decision. It requires LOTOR_CONTROL_URL and LOTOR_API_KEY.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/2kims/lotor-go/lotor"
)

func main() {
	resolver, err := lotor.NewOwnershipResolver(lotor.DiscoveryOptions{
		ControlURL: os.Getenv("LOTOR_CONTROL_URL"),
		APIKey:     os.Getenv("LOTOR_API_KEY"),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	decision, err := lotor.WithOwnerRetry(ctx, resolver, nil, func(client *lotor.Client) (lotor.Decision, error) {
		return client.AccessCheck("user:42", "view", "document:99")
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("allow=%t reason=%s\n", decision.Allow, decision.Reason)
}
