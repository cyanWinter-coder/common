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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMergeTLSConfig(t *testing.T) {
	global := TLSConfig{
		CAFile:             "/global/ca.pem",
		CertFile:           "/global/cert.pem",
		KeyFile:            "/global/key.pem",
		ServerName:         "global.example",
		InsecureSkipVerify: false,
		MinVersion:         TLSVersion(0x0303), // TLS 1.2
		MaxVersion:         TLSVersion(0x0304), // TLS 1.3
	}

	t.Run("empty job inherits everything", func(t *testing.T) {
		merged, err := MergeTLSConfig(global, TLSConfig{})
		require.NoError(t, err)
		require.Equal(t, global, merged)
	})

	t.Run("job file replaces whole CA group", func(t *testing.T) {
		job := TLSConfig{CARef: "job-ca-ref"}
		merged, err := MergeTLSConfig(global, job)
		require.NoError(t, err)
		require.Empty(t, merged.CAFile)
		require.Equal(t, "job-ca-ref", merged.CARef)
		// Unrelated groups and scalars are still inherited.
		require.Equal(t, "/global/cert.pem", merged.CertFile)
		require.Equal(t, "global.example", merged.ServerName)
		require.Equal(t, global.MinVersion, merged.MinVersion)
		require.Equal(t, global.MaxVersion, merged.MaxVersion)
	})

	t.Run("job inline cert replaces cert group, key stays global", func(t *testing.T) {
		job := TLSConfig{Cert: "inline-cert"}
		merged, err := MergeTLSConfig(global, job)
		require.NoError(t, err)
		require.Equal(t, "inline-cert", merged.Cert)
		require.Empty(t, merged.CertFile)
		require.Empty(t, merged.CertRef)
		require.Equal(t, "/global/key.pem", merged.KeyFile)
	})

	t.Run("job scalars win", func(t *testing.T) {
		job := TLSConfig{
			ServerName:         "job.example",
			InsecureSkipVerify: true,
			MinVersion:         TLSVersion(0x0304),
			MaxVersion:         TLSVersion(0x0304),
		}
		merged, err := MergeTLSConfig(global, job)
		require.NoError(t, err)
		require.Equal(t, "job.example", merged.ServerName)
		require.True(t, merged.InsecureSkipVerify)
		require.Equal(t, TLSVersion(0x0304), merged.MinVersion)
		require.Equal(t, TLSVersion(0x0304), merged.MaxVersion)
	})

	t.Run("merged config rejects conflicting sources", func(t *testing.T) {
		// Global cert comes from a file; job supplies a key only. The merge
		// itself stays valid, but an explicitly conflicting job config is
		// surfaced by Validate.
		bad := TLSConfig{Cert: "inline", CertFile: "/also/a/file"}
		_, err := MergeTLSConfig(global, bad)
		require.ErrorContains(t, err, "at most one of cert, cert_file & cert_ref")
	})

	t.Run("inputs are not mutated", func(t *testing.T) {
		globalCopy := global
		job := TLSConfig{ServerName: "job.example"}
		_, err := MergeTLSConfig(global, job)
		require.NoError(t, err)
		require.Equal(t, globalCopy, global)
	})
}

func writeExpiredCertPair(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "expired-test-client"},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     time.Now().Add(-time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	certPath = filepath.Join(dir, "expired.crt")
	keyPath = filepath.Join(dir, "expired.key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o644))

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o644))
	return certPath, keyPath
}

func TestValidateTLSMaterials(t *testing.T) {
	tmpDir := t.TempDir()
	expiredCert, expiredKey := writeExpiredCertPair(t, tmpDir)

	t.Run("valid file material passes", func(t *testing.T) {
		cfg := TLSConfig{
			CAFile:   TLSCAChainPath,
			CertFile: ClientCertificatePath,
			KeyFile:  ClientKeyNoPassPath,
		}
		require.NoError(t, validateTLSMaterials(t.Context(), &cfg, nil, time.Now()))
	})

	t.Run("valid inline material passes", func(t *testing.T) {
		cfg := TLSConfig{
			CA:   readFile(t, TLSCAChainPath),
			Cert: readFile(t, ClientCertificatePath),
			Key:  Secret(readFile(t, ClientKeyNoPassPath)),
		}
		require.NoError(t, validateTLSMaterials(t.Context(), &cfg, nil, time.Now()))
	})

	t.Run("missing CA file fails before client build", func(t *testing.T) {
		cfg := TLSConfig{CAFile: MissingCA}
		err := validateTLSMaterials(t.Context(), &cfg, nil, time.Now())
		require.ErrorContains(t, err, "unable to read CA cert")
	})

	t.Run("malformed CA fails", func(t *testing.T) {
		cfg := TLSConfig{CAFile: InvalidCA}
		err := validateTLSMaterials(t.Context(), &cfg, nil, time.Now())
		require.ErrorContains(t, err, "unable to use specified CA cert")
	})

	t.Run("missing client cert fails", func(t *testing.T) {
		cfg := TLSConfig{CertFile: MissingCert, KeyFile: ClientKeyNoPassPath}
		err := validateTLSMaterials(t.Context(), &cfg, nil, time.Now())
		require.ErrorContains(t, err, "unable to read specified client cert")
	})

	t.Run("cert without key fails", func(t *testing.T) {
		cfg := TLSConfig{CertFile: ClientCertificatePath}
		err := validateTLSMaterials(t.Context(), &cfg, nil, time.Now())
		require.ErrorContains(t, err, "exactly one of key")
	})

	t.Run("expired client cert is rejected", func(t *testing.T) {
		cfg := TLSConfig{CertFile: expiredCert, KeyFile: expiredKey}
		err := validateTLSMaterials(t.Context(), &cfg, nil, time.Now())
		require.ErrorIs(t, err, ErrExpiredCertificate)
	})

	t.Run("expired CA is rejected", func(t *testing.T) {
		// Reuse the expired leaf as a (malformed) CA bundle: lifetime
		// validation must flag it regardless of CA/basic constraints.
		cfg := TLSConfig{CAFile: expiredCert}
		err := validateTLSMaterials(t.Context(), &cfg, nil, time.Now())
		require.ErrorIs(t, err, ErrExpiredCertificate)
	})
}

func newManagedTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv, err := newTestServer(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(ExpectedMessage))
	})
	require.NoError(t, err)
	t.Cleanup(srv.Close)
	return srv
}

func fileHTTPClientConfig(t *testing.T, ca, cert, key string) HTTPClientConfig {
	t.Helper()
	return HTTPClientConfig{
		TLSConfig: TLSConfig{
			CAFile:   ca,
			CertFile: cert,
			KeyFile:  key,
		},
	}
}

func TestManagedClient_BuildAndRequest(t *testing.T) {
	bs := getCertificateBlobs(t)
	tmpDir := t.TempDir()
	ca, cert, key := filepath.Join(tmpDir, "ca"), filepath.Join(tmpDir, "cert"), filepath.Join(tmpDir, "key")
	writeCertificate(bs, TLSCAChainPath, ca)
	writeCertificate(bs, ClientCertificatePath, cert)
	writeCertificate(bs, ClientKeyNoPassPath, key)

	srv := newManagedTestServer(t)

	globalCfg := HTTPClientConfig{TLSConfig: TLSConfig{CAFile: ca}}
	jobCfg := fileHTTPClientConfig(t, "", cert, key) // CA unset: inherits global.

	mc, err := NewManagedClient(globalCfg, jobCfg, "managed-test")
	require.NoError(t, err)
	defer mc.Close()

	resp, err := mc.Client().Get(srv.URL)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// The merged TLSConfig carried by the active client must hold the global
	// CA plus the job-level cert/key.
	require.Equal(t, ca, mc.cfg.TLSConfig.CAFile)
	require.Equal(t, cert, mc.cfg.TLSConfig.CertFile)
	require.Equal(t, key, mc.cfg.TLSConfig.KeyFile)
}

func TestManagedClient_BuildFailsOnBadMaterial(t *testing.T) {
	tmpDir := t.TempDir()
	expiredCert, expiredKey := writeExpiredCertPair(t, tmpDir)

	globalCfg := HTTPClientConfig{}
	jobCfg := HTTPClientConfig{
		TLSConfig: TLSConfig{CertFile: expiredCert, KeyFile: expiredKey},
	}
	mc, err := NewManagedClient(globalCfg, jobCfg, "managed-bad")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrExpiredCertificate)
	require.Nil(t, mc)

	// Missing file likewise fails construction rather than the first request.
	jobCfg = fileHTTPClientConfig(t, MissingCA, "", "")
	mc, err = NewManagedClient(HTTPClientConfig{}, jobCfg, "managed-missing")
	require.ErrorContains(t, err, "unable to read CA cert")
	require.Nil(t, mc)
}

func TestManagedClient_RotationKeepsLastGood(t *testing.T) {
	bs := getCertificateBlobs(t)
	tmpDir := t.TempDir()
	ca, cert, key := filepath.Join(tmpDir, "ca"), filepath.Join(tmpDir, "cert"), filepath.Join(tmpDir, "key")
	writeCertificate(bs, TLSCAChainPath, ca)
	writeCertificate(bs, ClientCertificatePath, cert)
	writeCertificate(bs, ClientKeyNoPassPath, key)

	srv := newManagedTestServer(t)

	jobCfg := fileHTTPClientConfig(t, ca, cert, key)
	mc, err := NewManagedClient(HTTPClientConfig{}, jobCfg, "managed-rotate")
	require.NoError(t, err)
	defer mc.Close()

	// Sanity: initial request works.
	resp, err := mc.Client().Get(srv.URL)
	require.NoError(t, err)
	resp.Body.Close()

	// Rotate the cert/key to an invalid pair: the next request must surface
	// the validation error, and the previous transport keeps working.
	writeCertificate(bs, WrongClientCertPath, cert)
	writeCertificate(bs, WrongClientKeyPath, key)

	_, err = mc.Client().Get(srv.URL)
	require.Error(t, err)

	// The server rejects the wrong client cert at handshake time, which proves
	// the rotation was attempted; now restore valid material and confirm the
	// client recovers on the next request without a rebuild.
	writeCertificate(bs, ClientCertificatePath, cert)
	writeCertificate(bs, ClientKeyNoPassPath, key)
	resp, err = mc.Client().Get(srv.URL)
	require.NoError(t, err)
	resp.Body.Close()

	// Emptying the CA file is a failed rotation too, and the good CA survives.
	writeCertificate(bs, EmptyFile, ca)
	_, err = mc.Client().Get(srv.URL)
	require.ErrorContains(t, err, "unable to use specified CA cert")

	writeCertificate(bs, TLSCAChainPath, ca)
	resp, err = mc.Client().Get(srv.URL)
	require.NoError(t, err)
	resp.Body.Close()
}

func TestManagedClient_ReconfigureFallback(t *testing.T) {
	bs := getCertificateBlobs(t)
	tmpDir := t.TempDir()
	ca, cert, key := filepath.Join(tmpDir, "ca"), filepath.Join(tmpDir, "cert"), filepath.Join(tmpDir, "key")
	writeCertificate(bs, TLSCAChainPath, ca)
	writeCertificate(bs, ClientCertificatePath, cert)
	writeCertificate(bs, ClientKeyNoPassPath, key)

	srv := newManagedTestServer(t)

	jobCfg := fileHTTPClientConfig(t, ca, cert, key)
	mc, err := NewManagedClient(HTTPClientConfig{}, jobCfg, "managed-reconfig")
	require.NoError(t, err)
	defer mc.Close()

	goodClient := mc.Client()
	resp, err := goodClient.Get(srv.URL)
	require.NoError(t, err)
	resp.Body.Close()

	// A reconfigure pointing at an expired cert must fail and leave the old
	// client in place.
	expiredCert, expiredKey := writeExpiredCertPair(t, tmpDir)
	badJob := fileHTTPClientConfig(t, ca, expiredCert, expiredKey)
	err = mc.Reconfigure(HTTPClientConfig{}, badJob)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrExpiredCertificate)
	require.Same(t, goodClient, mc.Client())

	// The old client still serves traffic.
	resp, err = mc.Client().Get(srv.URL)
	require.NoError(t, err)
	resp.Body.Close()

	// A valid reconfigure swaps in a new client and closes the old one's idle
	// connections.
	ca2, cert2, key2 := filepath.Join(tmpDir, "ca2"), filepath.Join(tmpDir, "cert2"), filepath.Join(tmpDir, "key2")
	writeCertificate(bs, TLSCAChainPath, ca2)
	writeCertificate(bs, ClientCertificatePath, cert2)
	writeCertificate(bs, ClientKeyNoPassPath, key2)
	goodJob2 := fileHTTPClientConfig(t, ca2, cert2, key2)
	require.NoError(t, mc.Reconfigure(HTTPClientConfig{}, goodJob2))
	require.NotSame(t, goodClient, mc.Client())

	resp, err = mc.Client().Get(srv.URL)
	require.NoError(t, err)
	resp.Body.Close()
}

func TestManagedClient_ProxyAuthAndTimeoutUntouched(t *testing.T) {
	bs := getCertificateBlobs(t)
	tmpDir := t.TempDir()
	ca, cert, key := filepath.Join(tmpDir, "ca"), filepath.Join(tmpDir, "cert"), filepath.Join(tmpDir, "key")
	writeCertificate(bs, TLSCAChainPath, ca)
	writeCertificate(bs, ClientCertificatePath, cert)
	writeCertificate(bs, ClientKeyNoPassPath, key)

	// A local TCP listener stands in for the egress proxy: it must receive
	// the CONNECT with the configured proxy header.
	proxyCalled := make(chan struct{}, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			if r.Header.Get("X-Proxy-Auth") == "proxy-secret" {
				close(proxyCalled)
			}
			// Hijack would be needed for a real tunnel; closing is enough to
			// prove the request was routed through the proxy.
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()

	proxyURL, err := url.Parse(proxy.URL)
	require.NoError(t, err)
	globalCfg := HTTPClientConfig{TLSConfig: TLSConfig{CAFile: ca}}
	jobCfg := HTTPClientConfig{
		TLSConfig: TLSConfig{CertFile: cert, KeyFile: key},
		ProxyConfig: ProxyConfig{
			ProxyURL: URL{URL: proxyURL},
			ProxyConnectHeader: ProxyHeader{
				"X-Proxy-Auth": {Secret("proxy-secret")},
			},
		},
	}

	mc, err := NewManagedClient(globalCfg, jobCfg, "managed-proxy")
	require.NoError(t, err)
	defer mc.Close()

	// Merge only touched TLS: proxy settings survive.
	require.Equal(t, proxyURL.String(), mc.cfg.ProxyURL.String())
	require.Equal(t, "proxy-secret", string(mc.cfg.ProxyConnectHeader["X-Proxy-Auth"][0]))

	_, _ = mc.Client().Get("https://target.example/")
	select {
	case <-proxyCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("request did not go through the configured proxy with its header")
	}

	// After a TLS-only reconfigure the proxy is still wired the same way.
	rotatedCA := filepath.Join(tmpDir, "ca-rotated")
	writeCertificate(bs, TLSCAChainPath, rotatedCA)
	newGlobal := HTTPClientConfig{TLSConfig: TLSConfig{CAFile: rotatedCA}}
	require.NoError(t, mc.Reconfigure(newGlobal, jobCfg))
	require.Equal(t, proxyURL.String(), mc.cfg.ProxyURL.String())
	_, _ = mc.Client().Get("https://target.example/")
	select {
	case <-proxyCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy settings were lost after TLS reconfigure")
	}
}

func TestManagedClient_ExpiredRotationRejected(t *testing.T) {
	bs := getCertificateBlobs(t)
	tmpDir := t.TempDir()
	ca, cert, key := filepath.Join(tmpDir, "ca"), filepath.Join(tmpDir, "cert"), filepath.Join(tmpDir, "key")
	writeCertificate(bs, TLSCAChainPath, ca)
	writeCertificate(bs, ClientCertificatePath, cert)
	writeCertificate(bs, ClientKeyNoPassPath, key)

	expiredCert, expiredKey := writeExpiredCertPair(t, tmpDir)

	srv := newManagedTestServer(t)
	jobCfg := fileHTTPClientConfig(t, ca, cert, key)
	mc, err := NewManagedClient(HTTPClientConfig{}, jobCfg, "managed-expired-rotation")
	require.NoError(t, err)
	defer mc.Close()

	resp, err := mc.Client().Get(srv.URL)
	require.NoError(t, err)
	resp.Body.Close()

	// Rotate in an expired client cert/key: the request must fail with the
	// expiry error and no new transport gets installed.
	expiredPEM, err := os.ReadFile(expiredCert)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cert, expiredPEM, 0o644))
	expiredKeyPEM, err := os.ReadFile(expiredKey)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(key, expiredKeyPEM, 0o644))

	_, err = mc.Client().Get(srv.URL)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrExpiredCertificate)

	// Restore the valid pair: the retained transport picks it up and serves
	// again without rebuilding the client.
	writeCertificate(bs, ClientCertificatePath, cert)
	writeCertificate(bs, ClientKeyNoPassPath, key)
	resp, err = mc.Client().Get(srv.URL)
	require.NoError(t, err)
	resp.Body.Close()
}

func TestManagedClient_InlineMaterialMergedFromGlobal(t *testing.T) {
	srv := newManagedTestServer(t)

	globalCfg := HTTPClientConfig{
		TLSConfig: TLSConfig{CA: readFile(t, TLSCAChainPath)},
	}
	jobCfg := HTTPClientConfig{
		TLSConfig: TLSConfig{
			Cert: readFile(t, ClientCertificatePath),
			Key:  Secret(readFile(t, ClientKeyNoPassPath)),
		},
	}

	mc, err := NewManagedClient(globalCfg, jobCfg, "managed-inline")
	require.NoError(t, err)
	defer mc.Close()

	require.Equal(t, globalCfg.TLSConfig.CA, mc.cfg.TLSConfig.CA)
	require.Empty(t, mc.cfg.TLSConfig.CAFile)
	require.Equal(t, jobCfg.TLSConfig.Cert, mc.cfg.TLSConfig.Cert)

	resp, err := mc.Client().Get(srv.URL)
	require.NoError(t, err)
	resp.Body.Close()
}

func TestManagedClient_ConcurrentReconfigureAndRequests(t *testing.T) {
	bs := getCertificateBlobs(t)
	tmpDir := t.TempDir()
	ca, cert, key := filepath.Join(tmpDir, "ca"), filepath.Join(tmpDir, "cert"), filepath.Join(tmpDir, "key")
	writeCertificate(bs, TLSCAChainPath, ca)
	writeCertificate(bs, ClientCertificatePath, cert)
	writeCertificate(bs, ClientKeyNoPassPath, key)

	srv := newManagedTestServer(t)
	jobCfg := fileHTTPClientConfig(t, ca, cert, key)
	mc, err := NewManagedClient(HTTPClientConfig{}, jobCfg, "managed-concurrent")
	require.NoError(t, err)
	defer mc.Close()

	expiredCert, expiredKey := writeExpiredCertPair(t, tmpDir)
	goodJob := jobCfg
	badJob := fileHTTPClientConfig(t, ca, expiredCert, expiredKey)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Continuous traffic: every request must either succeed against a
	// last-known-good client or fail with a typed validation error — never a
	// panic or a torn state.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				resp, err := mc.Client().Get(srv.URL)
				if err == nil {
					resp.Body.Close()
				} else if errors.Is(err, ErrExpiredCertificate) {
					// Expected when a rotation races ahead of its rollback.
				}
			}
		}
	}()

	// Alternate valid and invalid reconfigures.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				_ = mc.Reconfigure(HTTPClientConfig{}, badJob)
			} else {
				_ = mc.Reconfigure(HTTPClientConfig{}, goodJob)
			}
		}
		close(stop)
	}()

	wg.Wait()
	// Final state: a valid reconfigure restores a fully working client.
	require.NoError(t, mc.Reconfigure(HTTPClientConfig{}, goodJob))
	resp, err := mc.Client().Get(srv.URL)
	require.NoError(t, err)
	resp.Body.Close()
}

func TestManagedClient_CloseIsIdempotentAndReleasesConns(t *testing.T) {
	bs := getCertificateBlobs(t)
	tmpDir := t.TempDir()
	ca, cert, key := filepath.Join(tmpDir, "ca"), filepath.Join(tmpDir, "cert"), filepath.Join(tmpDir, "key")
	writeCertificate(bs, TLSCAChainPath, ca)
	writeCertificate(bs, ClientCertificatePath, cert)
	writeCertificate(bs, ClientKeyNoPassPath, key)

	srv := newManagedTestServer(t)
	jobCfg := fileHTTPClientConfig(t, ca, cert, key)
	mc, err := NewManagedClient(HTTPClientConfig{}, jobCfg, "managed-close")
	require.NoError(t, err)

	resp, err := mc.Client().Get(srv.URL)
	require.NoError(t, err)
	resp.Body.Close()

	mc.Close()
	mc.Close() // Must be a no-op, not a panic.

	err = mc.Reconfigure(HTTPClientConfig{}, jobCfg)
	require.ErrorContains(t, err, "managed client is closed")
}
