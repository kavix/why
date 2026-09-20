package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/kavix/why/internal/adapters"
	"github.com/kavix/why/internal/model"
)

type TLSAdapter struct{}

func New() *TLSAdapter {
	return &TLSAdapter{}
}

func (a *TLSAdapter) Name() string     { return "tls" }
func (a *TLSAdapter) Protocol() string { return "tls" }

func (a *TLSAdapter) CanHandle(target string) bool {
	clean := strings.TrimSpace(target)
	if strings.HasPrefix(clean, "tls ") || strings.HasPrefix(clean, "ssl ") {
		return true
	}
	return false
}

func (a *TLSAdapter) Diagnose(ctx context.Context, target string, opts adapters.DiagnosticOptions) (*model.Diagnostic, error) {
	target = strings.TrimPrefix(target, "tls ")
	target = strings.TrimPrefix(target, "ssl ")
	target = strings.TrimPrefix(target, "https://")

	host := target
	port := 443
	if strings.Contains(target, ":") {
		h, p, err := net.SplitHostPort(target)
		if err == nil {
			host = h
			port, _ = strconv.Atoi(p)
		}
	}

	return DiagnoseTLS(ctx, host, port, opts)
}

// DiagnoseTLS executes certificate, SNI, and handshake verification
func DiagnoseTLS(ctx context.Context, host string, port int, opts adapters.DiagnosticOptions) (*model.Diagnostic, error) {
	target := fmt.Sprintf("%s:%d", host, port)
	diag := &model.Diagnostic{
		Target:    target,
		Protocol:  "tls",
		Timestamp: time.Now(),
		Status:    "passed",
		Metadata: map[string]interface{}{
			"host": host,
			"port": port,
		},
	}

	startTotal := time.Now()

	// 1. Resolve host
	c1Start := time.Now()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	c1Dur := time.Since(c1Start)
	if err != nil {
		diag.Status = "failed"
		diag.FailedAt = "dns"
		diag.Checks = append(diag.Checks, model.Check{
			Name:        "DNS Resolution",
			Stage:       "dns",
			Status:      model.StatusFailed,
			Duration:    c1Dur,
			DurationStr: c1Dur.String(),
			Error:       err.Error(),
		})
		diag.Failure = &model.Failure{
			Stage:  "dns",
			Check:  "DNS Resolution",
			Reason: fmt.Sprintf("Failed to resolve %s: %v", host, err),
		}
		diag.TotalElapsed = time.Since(startTotal).String()
		return diag, nil
	}

	diag.Checks = append(diag.Checks, model.Check{
		Name:        "DNS Resolution",
		Stage:       "dns",
		Status:      model.StatusPassed,
		Duration:    c1Dur,
		DurationStr: c1Dur.String(),
		Summary:     fmt.Sprintf("Resolved %s", ips[0].IP.String()),
	})

	// 2. TCP connect
	c2Start := time.Now()
	dialer := net.Dialer{Timeout: 4 * time.Second}
	addr := net.JoinHostPort(ips[0].IP.String(), strconv.Itoa(port))
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	c2Dur := time.Since(c2Start)
	if err != nil {
		diag.Status = "failed"
		diag.FailedAt = "tcp"
		diag.Checks = append(diag.Checks, model.Check{
			Name:        fmt.Sprintf("TCP Connect :%d", port),
			Stage:       "tcp",
			Status:      model.StatusFailed,
			Duration:    c2Dur,
			DurationStr: c2Dur.String(),
			Error:       err.Error(),
		})
		diag.Failure = &model.Failure{
			Stage:  "tcp",
			Check:  fmt.Sprintf("TCP Connect :%d", port),
			Reason: fmt.Sprintf("TCP port %d connection failed: %v", port, err),
		}
		diag.TotalElapsed = time.Since(startTotal).String()
		return diag, nil
	}

	diag.Checks = append(diag.Checks, model.Check{
		Name:        fmt.Sprintf("TCP Connect :%d", port),
		Stage:       "tcp",
		Status:      model.StatusPassed,
		Duration:    c2Dur,
		DurationStr: c2Dur.String(),
		Summary:     fmt.Sprintf("Connected in %v", c2Dur),
	})

	// 3. TLS Handshake with validation
	c3Start := time.Now()
	tlsConfig := &tls.Config{
		ServerName: host,
	}
	tlsConn := tls.Client(conn, tlsConfig)
	handshakeErr := tlsConn.HandshakeContext(ctx)
	c3Dur := time.Since(c3Start)

	if handshakeErr != nil {
		diag.Status = "failed"
		diag.FailedAt = "tls_handshake"

		evidence := map[string]interface{}{
			"host":      host,
			"sni":       host,
			"raw_error": handshakeErr.Error(),
		}

		reason := "TLS Handshake failed"
		errStr := handshakeErr.Error()

		// Distinguish specific TLS certificate errors
		if strings.Contains(errStr, "certificate has expired") {
			reason = "Certificate has expired"
			evidence["tls_issue"] = "CERT_EXPIRED"
		} else if strings.Contains(errStr, "certificate is not valid for any names") || strings.Contains(errStr, "certificate is valid for") {
			reason = "Hostname mismatch: server certificate does not match requested domain"
			evidence["tls_issue"] = "HOSTNAME_MISMATCH"
		} else if isUntrustedCertificateError(errStr) {
			reason = "Untrusted Certificate Authority (Self-signed certificate or missing intermediate CA)"
			evidence["tls_issue"] = "UNTRUSTED_ROOT_OR_SELF_SIGNED"
		} else if strings.Contains(errStr, "handshake failure") {
			reason = "TLS protocol/cipher suite negotiation failure"
			evidence["tls_issue"] = "CIPHER_MISMATCH"
		}

		// Try unverified handshake to collect cert evidence even on failure
		unverifiedConn, uErr := dialer.DialContext(ctx, "tcp", addr)
		if uErr == nil {
			insecureTLS := tls.Client(unverifiedConn, &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: true,
			})
			if insecureTLS.HandshakeContext(ctx) == nil {
				state := insecureTLS.ConnectionState()
				if len(state.PeerCertificates) > 0 {
					cert := state.PeerCertificates[0]
					evidence["subject"] = cert.Subject.CommonName
					evidence["issuer"] = cert.Issuer.CommonName
					evidence["valid_from"] = cert.NotBefore.Format(time.RFC3339)
					evidence["valid_to"] = cert.NotAfter.Format(time.RFC3339)
					evidence["dns_sans"] = cert.DNSNames
					evidence["days_remaining"] = int(time.Until(cert.NotAfter).Hours() / 24)

					// Some platform verifiers report an untrusted issuer before
					// more specific certificate problems. Inspect the peer
					// certificate itself so those problems are not misclassified.
					if time.Now().After(cert.NotAfter) {
						reason = "Certificate has expired"
						evidence["tls_issue"] = "CERT_EXPIRED"
					} else if cert.VerifyHostname(host) != nil {
						reason = "Hostname mismatch: server certificate does not match requested domain"
						evidence["tls_issue"] = "HOSTNAME_MISMATCH"
					}
				}
			}
			unverifiedConn.Close()
		}

		diag.Checks = append(diag.Checks, model.Check{
			Name:        "TLS Handshake",
			Stage:       "tls",
			Status:      model.StatusFailed,
			Duration:    c3Dur,
			DurationStr: c3Dur.String(),
			Error:       handshakeErr.Error(),
			Evidence:    evidence,
		})

		diag.Failure = &model.Failure{
			Stage:    "tls_handshake",
			Check:    "TLS Handshake",
			Reason:   reason,
			Evidence: evidence,
		}

		diag.TotalElapsed = time.Since(startTotal).String()
		return diag, nil
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	peerCert := state.PeerCertificates[0]
	daysUntilExpiry := int(time.Until(peerCert.NotAfter).Hours() / 24)

	tlsVersionStr := "TLS 1.2"
	if state.Version == tls.VersionTLS13 {
		tlsVersionStr = "TLS 1.3"
	}

	diag.Checks = append(diag.Checks, model.Check{
		Name:        "TLS Handshake",
		Stage:       "tls",
		Status:      model.StatusPassed,
		Duration:    c3Dur,
		DurationStr: c3Dur.String(),
		Summary:     fmt.Sprintf("%s, cipher: %s", tlsVersionStr, tls.CipherSuiteName(state.CipherSuite)),
		Evidence: map[string]interface{}{
			"version":      tlsVersionStr,
			"cipher_suite": tls.CipherSuiteName(state.CipherSuite),
			"alpn":         state.NegotiatedProtocol,
		},
	})

	// 4. Certificate Expiration & Validity Check
	certCheckStatus := model.StatusPassed
	var certWarning string
	if daysUntilExpiry <= 0 {
		certCheckStatus = model.StatusFailed
		certWarning = "Certificate is EXPIRED"
	} else if daysUntilExpiry < 14 {
		certCheckStatus = model.StatusWarning
		certWarning = fmt.Sprintf("Certificate expires soon (%d days remaining)", daysUntilExpiry)
	}

	diag.Checks = append(diag.Checks, model.Check{
		Name:        "Certificate Trust & Expiration",
		Stage:       "certificate",
		Status:      certCheckStatus,
		Duration:    1 * time.Millisecond,
		DurationStr: "1ms",
		Summary:     fmt.Sprintf("Issuer: %s, Valid for %d more days", peerCert.Issuer.CommonName, daysUntilExpiry),
		Error:       certWarning,
		Evidence: map[string]interface{}{
			"subject":        peerCert.Subject.CommonName,
			"issuer":         peerCert.Issuer.CommonName,
			"not_before":     peerCert.NotBefore.Format(time.RFC3339),
			"not_after":      peerCert.NotAfter.Format(time.RFC3339),
			"days_remaining": daysUntilExpiry,
			"sans":           peerCert.DNSNames,
		},
	})

	if certCheckStatus == model.StatusFailed {
		diag.Status = "failed"
		diag.FailedAt = "certificate_expired"
		diag.Failure = &model.Failure{
			Stage:  "certificate",
			Check:  "Certificate Trust & Expiration",
			Reason: fmt.Sprintf("Certificate for %s expired on %s", host, peerCert.NotAfter.Format(time.RFC822)),
		}
	}

	diag.TotalElapsed = time.Since(startTotal).String()
	return diag, nil
}

func isUntrustedCertificateError(err string) bool {
	return strings.Contains(err, "unknown authority") ||
		strings.Contains(err, "certificate signed by unknown authority") ||
		strings.Contains(err, "certificate is not trusted")
}

func VerifyHostname(cert *x509.Certificate, host string) bool {
	return cert.VerifyHostname(host) == nil
}
