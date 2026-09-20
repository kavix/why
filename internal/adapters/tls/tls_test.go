package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/kavix/why/internal/adapters"
)

func TestDiagnoseTLSIdentifiesCertificateFailures(t *testing.T) {
	now := time.Now()
	validForIP := func(ip string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(now.UnixNano()),
			Subject:               pkix.Name{CommonName: "test certificate"},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			IsCA:                  true,
			IPAddresses:           []net.IP{net.ParseIP(ip)},
		}
	}

	tests := []struct {
		name string
		cert tls.Certificate
		want string
	}{
		{
			name: "expired certificate",
			cert: selfSignedCertificate(t, validForIP("127.0.0.1"), now.Add(-48*time.Hour), now.Add(-24*time.Hour)),
			want: "CERT_EXPIRED",
		},
		{
			name: "hostname mismatch",
			cert: selfSignedCertificate(t, validForIP("127.0.0.2"), now.Add(-time.Hour), now.Add(time.Hour)),
			want: "HOSTNAME_MISMATCH",
		},
		{
			name: "self-signed certificate",
			cert: selfSignedCertificate(t, validForIP("127.0.0.1"), now.Add(-time.Hour), now.Add(time.Hour)),
			want: "UNTRUSTED_ROOT_OR_SELF_SIGNED",
		},
		{
			name: "untrusted root",
			cert: certificateSignedByUnknownRoot(t, validForIP("127.0.0.1")),
			want: "UNTRUSTED_ROOT_OR_SELF_SIGNED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			address := serveTLSCertificate(t, tt.cert)
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				t.Fatalf("split test listener address: %v", err)
			}

			portNumber, err := net.LookupPort("tcp", port)
			if err != nil {
				t.Fatalf("parse test listener port: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			diag, err := DiagnoseTLS(ctx, host, portNumber, adapters.DiagnosticOptions{})
			if err != nil {
				t.Fatalf("DiagnoseTLS returned an error: %v", err)
			}
			if diag.Status != "failed" {
				t.Fatalf("status = %q, want failed", diag.Status)
			}
			if diag.Failure == nil {
				t.Fatal("failure details are missing")
			}
			if got, _ := diag.Failure.Evidence["tls_issue"].(string); got != tt.want {
				t.Errorf("tls_issue = %q, want %q (raw error: %v)", got, tt.want, diag.Failure.Evidence["raw_error"])
			}
		})
	}
}

func serveTLSCertificate(t *testing.T, cert tls.Certificate) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for TLS fixture: %v", err)
	}
	server := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{cert}})
	t.Cleanup(func() { _ = server.Close() })

	go func() {
		for {
			conn, err := server.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if tlsConn, ok := conn.(*tls.Conn); ok {
					_ = tlsConn.Handshake()
				}
			}()
		}
	}()

	return listener.Addr().String()
}

func selfSignedCertificate(t *testing.T, template *x509.Certificate, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test certificate key: %v", err)
	}
	template.NotBefore = notBefore
	template.NotAfter = notAfter
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func certificateSignedByUnknownRoot(t *testing.T, leafTemplate *x509.Certificate) tls.Certificate {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test root key: %v", err)
	}
	now := time.Now()
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "test-only unknown root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create test root certificate: %v", err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse test root certificate: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test leaf key: %v", err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create test leaf certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
}
