// Package baospike is a minimal OpenBao client for this spike: stdlib
// net/http only, no SDK, following the house pattern in
// keyring/keymanager/openbaotransit.
package baospike

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client addresses one OpenBao server with one token.
type Client struct {
	Address string
	Token   string
	HTTP    *http.Client
}

func New(address, token string) *Client {
	return &Client{
		Address: strings.TrimSuffix(address, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// Response is the envelope every OpenBao API call returns.
type Response struct {
	RequestID     string          `json:"request_id"`
	LeaseID       string          `json:"lease_id"`
	Renewable     bool            `json:"renewable"`
	LeaseDuration int             `json:"lease_duration"`
	Data          json.RawMessage `json:"data"`
	Warnings      []string        `json:"warnings"`
}

// Credential is the username/password pair a database role issues.
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Do performs one request and returns the decoded envelope. A non-2xx is an
// error carrying the body, because for this spike the exact error text from
// OpenBao is part of the measurement.
func (c *Client) Do(ctx context.Context, method, path string, body any) (*Response, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode %s %s: %w", method, path, err)
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Address+"/v1/"+strings.TrimPrefix(path, "/"), reader)
	if err != nil {
		return nil, fmt.Errorf("build %s %s: %w", method, path, err)
	}
	req.Header.Set("X-Vault-Token", c.Token)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return &Response{}, nil
	}
	var out Response
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode %s %s: %w", method, path, err)
	}
	return &out, nil
}

// Creds issues a dynamic credential from a database role.
func (c *Client) Creds(ctx context.Context, role string) (Credential, *Response, error) {
	resp, err := c.Do(ctx, http.MethodGet, "database/creds/"+role, nil)
	if err != nil {
		return Credential{}, nil, err
	}
	var cred Credential
	if err := json.Unmarshal(resp.Data, &cred); err != nil {
		return Credential{}, nil, fmt.Errorf("decode credential for %s: %w", role, err)
	}
	return cred, resp, nil
}

// StaticCreds reads the current credential of a static role.
func (c *Client) StaticCreds(ctx context.Context, role string) (Credential, *Response, error) {
	resp, err := c.Do(ctx, http.MethodGet, "database/static-creds/"+role, nil)
	if err != nil {
		return Credential{}, nil, err
	}
	var cred Credential
	if err := json.Unmarshal(resp.Data, &cred); err != nil {
		return Credential{}, nil, fmt.Errorf("decode static credential for %s: %w", role, err)
	}
	return cred, resp, nil
}

// LeaseLookup reads a lease's metadata, which is how a client would learn
// its own remaining TTL.
func (c *Client) LeaseLookup(ctx context.Context, leaseID string) (*Response, error) {
	return c.Do(ctx, http.MethodPut, "sys/leases/lookup", map[string]string{"lease_id": leaseID})
}

// RevokeLease revokes a lease immediately, which is what expiry does on a
// timer.
func (c *Client) RevokeLease(ctx context.Context, leaseID string) error {
	_, err := c.Do(ctx, http.MethodPut, "sys/leases/revoke", map[string]string{"lease_id": leaseID})
	return err
}
