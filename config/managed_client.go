// Copyright 2026 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// MergeTLSConfig merges a global TLS configuration with a job-level one.
//
// For every field, an explicit (non-zero) value in the job configuration takes
// precedence; fields the job leaves unset are inherited from the global
// configuration. The three material groups (CA, client certificate, client
// key) are each merged as a whole across their inline text, file and ref
// variants: if the job sets any variant of a group, it fully replaces the
// global group instead of mixing sources.
//
// The returned configuration is validated. Neither input is modified.
func MergeTLSConfig(global, job TLSConfig) (TLSConfig, error) {
	merged := global

	// CA: any explicit job source replaces the whole CA group.
	if job.CA != "" || job.CAFile != "" || job.CARef != "" {
		merged.CA, merged.CAFile, merged.CARef = job.CA, job.CAFile, job.CARef
	}
	// Client certificate.
	if job.Cert != "" || job.CertFile != "" || job.CertRef != "" {
		merged.Cert, merged.CertFile, merged.CertRef = job.Cert, job.CertFile, job.CertRef
	}
	// Client key.
	if job.Key != "" || job.KeyFile != "" || job.KeyRef != "" {
		merged.Key, merged.KeyFile, merged.KeyRef = job.Key, job.KeyFile, job.KeyRef
	}

	if job.ServerName != "" {
		merged.ServerName = job.ServerName
	}
	if job.InsecureSkipVerify {
		merged.InsecureSkipVerify = true
	}
	if job.MinVersion != 0 {
		merged.MinVersion = job.MinVersion
	}
	if job.MaxVersion != 0 {
		merged.MaxVersion = job.MaxVersion
	}

	if err := merged.Validate(); err != nil {
		return TLSConfig{}, err
	}
	return merged, nil
}

// ErrExpiredCertificate is returned when TLS material contains a certificate
// that is not valid at the validation time.
var ErrExpiredCertificate = errors.New("certificate is expired or not yet valid")

// verifyCertificateLifetime parses the PEM-encoded certificates in b and
// ensures each one is valid at now. The first invalid certificate produces an
// ErrExpiredCertificate error wrapping the underlying x509 error.
func verifyCertificateLifetime(b []byte, now time.Time) error {
	remaining := b
	for {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			return nil
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("unable to parse certificate: %w", err)
		}
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return fmt.Errorf("%w: notBefore=%s notAfter=%s", ErrExpiredCertificate, cert.NotBefore.UTC(), cert.NotAfter.UTC())
		}
	}
}

// validateTLSMaterials loads the CA, client certificate and key backing the
// TLSConfig and fails early if any material is missing, unreadable, malformed
// or (for certificates) outside its validity window. It mirrors the loading
// performed when building a tls.Config so that an unusable configuration is
// rejected before any client is constructed instead of failing on the first
// request.
func validateTLSMaterials(ctx context.Context, cfg *TLSConfig, secretManager SecretManager, now time.Time) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	caSecret, err := toSecret(secretManager, Secret(cfg.CA), cfg.CAFile, cfg.CARef)
	if err != nil {
		return fmt.Errorf("unable to use CA cert: %w", err)
	}
	if caSecret != nil {
		ca, err := caSecret.Fetch(ctx)
		if err != nil {
			return fmt.Errorf("unable to read CA cert: %w", err)
		}
		var root tls.Config
		if !updateRootCA(&root, []byte(ca)) {
			return fmt.Errorf("unable to use specified CA cert %s", caSecret.Description())
		}
		if err := verifyCertificateLifetime([]byte(ca), now); err != nil {
			return fmt.Errorf("CA cert %s: %w", caSecret.Description(), err)
		}
	}

	if cfg.usingClientCert() || cfg.usingClientKey() {
		// getClientCertificate pairs and parses the cert/key, covering missing
		// files, bad PEM and cert/key mismatches.
		clientCert, err := cfg.getClientCertificate(ctx, secretManager)
		if err != nil {
			return err
		}
		for _, c := range clientCert.Certificate {
			parsed, err := x509.ParseCertificate(c)
			if err != nil {
				return fmt.Errorf("unable to parse client certificate: %w", err)
			}
			if now.Before(parsed.NotBefore) || now.After(parsed.NotAfter) {
				return fmt.Errorf("client certificate: %w: notBefore=%s notAfter=%s", ErrExpiredCertificate, parsed.NotBefore.UTC(), parsed.NotAfter.UTC())
			}
		}
	}
	return nil
}

// ManagedClient wraps an *http.Client whose TLS material may rotate while the
// client stays in use. Certificate and key files are re-read on the next
// request after they change; a rotation that fails validation keeps serving
// traffic with the last known good configuration.
//
// Proxy, authentication headers and timeouts are fixed at construction time
// and are never touched by TLS rotations.
type ManagedClient struct {
	name    string
	opts    []HTTPClientOption
	nowFunc func() time.Time

	mtx    sync.RWMutex
	client *http.Client
	cfg    HTTPClientConfig
	closed bool
}

// NewManagedClient builds a ManagedClient from a global and a job-level HTTP
// client configuration. The two TLS sections are merged field by field with
// MergeTLSConfig (job values win, unset values inherit the global one); every
// other HTTP setting (proxy, authentication, headers, redirects, ...) is taken
// solely from jobCfg.
//
// It returns an error, without constructing a client, when the merged TLS
// material cannot be loaded or contains an expired certificate.
func NewManagedClient(globalCfg, jobCfg HTTPClientConfig, name string, optFuncs ...HTTPClientOption) (*ManagedClient, error) {
	return NewManagedClientWithContext(context.Background(), globalCfg, jobCfg, name, optFuncs...)
}

// NewManagedClientWithContext is NewManagedClient with a caller-supplied
// context used for the initial secret loads.
func NewManagedClientWithContext(ctx context.Context, globalCfg, jobCfg HTTPClientConfig, name string, optFuncs ...HTTPClientOption) (*ManagedClient, error) {
	mergedTLS, err := MergeTLSConfig(globalCfg.TLSConfig, jobCfg.TLSConfig)
	if err != nil {
		return nil, err
	}
	jobCfg.TLSConfig = mergedTLS

	// NewClientFromConfig runs validateTLSMaterials before constructing the
	// transport, so missing or expired material fails here rather than on the
	// first request.
	client, err := NewClientFromConfig(jobCfg, name, optFuncs...)
	if err != nil {
		return nil, err
	}

	return &ManagedClient{
		name:    name,
		opts:    optFuncs,
		nowFunc: time.Now,
		client:  client,
		cfg:     jobCfg,
	}, nil
}

// Client returns the currently active HTTP client. After a successful
// Reconfigure it returns the new client; callers that cache the returned
// pointer should re-fetch it.
func (m *ManagedClient) Client() *http.Client {
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	return m.client
}

// Reconfigure replaces the job-level configuration. The TLS section is merged
// again with globalCfg, validated (missing or expired material makes the call
// fail), and only then swapped in. On failure the previously active client and
// its last-known-good TLS configuration keep serving requests.
//
// Proxy, authentication and timeout changes are part of jobCfg and take effect
// on the new client; they are never derived from or overwritten by the TLS
// merge.
func (m *ManagedClient) Reconfigure(globalCfg, jobCfg HTTPClientConfig) error {
	return m.ReconfigureWithContext(context.Background(), globalCfg, jobCfg)
}

// ReconfigureWithContext is Reconfigure with a caller-supplied context.
func (m *ManagedClient) ReconfigureWithContext(ctx context.Context, globalCfg, jobCfg HTTPClientConfig) error {
	mergedTLS, err := MergeTLSConfig(globalCfg.TLSConfig, jobCfg.TLSConfig)
	if err != nil {
		return err
	}
	jobCfg.TLSConfig = mergedTLS

	m.mtx.RLock()
	nowFunc := m.nowFunc
	closed := m.closed
	m.mtx.RUnlock()

	secretManager := secretManagerFromOptions(m.opts)
	if err := validateTLSMaterials(ctx, &mergedTLS, secretManager, nowFunc()); err != nil {
		return err
	}

	newClient, err := NewClientFromConfig(jobCfg, m.name, m.opts...)
	if err != nil {
		return err
	}

	m.mtx.Lock()
	if closed {
		m.mtx.Unlock()
		closeClientIdleConnections(newClient)
		return errors.New("managed client is closed")
	}
	old := m.client
	m.client = newClient
	m.cfg = jobCfg
	m.mtx.Unlock()

	// Drop idle conns of the old client so its file handles can be reclaimed.
	closeClientIdleConnections(old)
	return nil
}

// Close releases idle connections (and their file handles) of the underlying
// client. It is safe to call multiple times.
func (m *ManagedClient) Close() {
	m.mtx.Lock()
	if m.closed {
		m.mtx.Unlock()
		return
	}
	m.closed = true
	client := m.client
	m.mtx.Unlock()

	closeClientIdleConnections(client)
}

// closeClientIdleConnections closes idle connections of every RoundTripper
// layer that supports it; the wrapping round trippers in this package all
// forward CloseIdleConnections down to the underlying http.Transport.
func closeClientIdleConnections(client *http.Client) {
	if client == nil {
		return
	}
	if ci, ok := client.Transport.(closeIdler); ok {
		ci.CloseIdleConnections()
	}
}

func secretManagerFromOptions(opts []HTTPClientOption) SecretManager {
	options := defaultHTTPClientOptions
	for _, opt := range opts {
		opt.applyToHTTPClientOptions(&options)
	}
	return options.secretManager
}
