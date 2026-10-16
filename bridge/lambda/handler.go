// Package lambda adapts API Gateway HTTP API payload version 2 events to the
// canonical bridge handler. Deployments enforce mTLS at their trusted gateway.
package lambda

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/2kims/lotor-go/bridge"
)

type Request struct {
	Headers        map[string]string `json:"headers"`
	Version        string            `json:"version"`
	RawPath        string            `json:"rawPath"`
	RawQueryString string            `json:"rawQueryString"`
	Body           string            `json:"body"`
	RequestContext struct {
		HTTP struct {
			Method string `json:"method"`
		} `json:"http"`
	} `json:"requestContext"`
	IsBase64Encoded bool `json:"isBase64Encoded"`
}

type Response struct {
	Headers         map[string]string `json:"headers"`
	Body            string            `json:"body"`
	StatusCode      int               `json:"statusCode"`
	IsBase64Encoded bool              `json:"isBase64Encoded"`
}

// NewHandler is compatible with lambda.Start in the deployment entry point.
// It has no AWS dependency and uses no event header as proof of authentication.
func NewHandler(runtime *bridge.Runtime) func(context.Context, Request) (Response, error) {
	return func(ctx context.Context, event Request) (Response, error) {
		invalid := Response{StatusCode: 400, Headers: map[string]string{"Content-Type": "application/json", "Cache-Control": "no-store"}, Body: `{"code":"invalid_request"}`}
		if runtime == nil || event.Version != "2.0" || len(event.Body) > base64.StdEncoding.EncodedLen(bridge.MaximumBodyBytes) || !strings.HasPrefix(event.RawPath, "/") || strings.ContainsAny(event.RawPath, "?#\r\n") {
			return invalid, nil
		}
		body := []byte(event.Body)
		if event.IsBase64Encoded {
			var err error
			body, err = base64.StdEncoding.Strict().DecodeString(event.Body)
			if err != nil {
				//nolint:nilerr // Malformed client input is an HTTP 400, not a Lambda invocation failure.
				return invalid, nil
			}
		}
		if len(body) > bridge.MaximumBodyBytes {
			return invalid, nil
		}
		path := "https://function.invalid" + event.RawPath
		if event.RawQueryString != "" {
			path += "?" + event.RawQueryString
		}
		request, err := http.NewRequestWithContext(ctx, event.RequestContext.HTTP.Method, path, strings.NewReader(string(body)))
		if err != nil {
			//nolint:nilerr // Malformed client input is an HTTP 400, not a Lambda invocation failure.
			return invalid, nil
		}
		for name, value := range event.Headers {
			request.Header.Add(name, value)
		}
		recorder := httptest.NewRecorder()
		runtime.ServeHTTP(recorder, request)
		headers := make(map[string]string)
		for name := range recorder.Header() {
			headers[name] = recorder.Header().Get(name)
		}
		return Response{StatusCode: recorder.Code, Headers: headers, Body: recorder.Body.String()}, nil
	}
}
