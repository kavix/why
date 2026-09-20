package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kavix/why/internal/adapters"
	"github.com/kavix/why/internal/model"
)

type HTTPAdapter struct{}

func New() *HTTPAdapter {
	return &HTTPAdapter{}
}

func (a *HTTPAdapter) Name() string     { return "http" }
func (a *HTTPAdapter) Protocol() string { return "http" }

func (a *HTTPAdapter) CanHandle(target string) bool {
	clean := strings.TrimSpace(target)
	if strings.HasPrefix(clean, "curl ") || strings.HasPrefix(clean, "http ") || strings.HasPrefix(clean, "https ") {
		return true
	}
	if strings.HasPrefix(clean, "http://") || strings.HasPrefix(clean, "https://") {
		return true
	}
	return false
}

func (a *HTTPAdapter) Diagnose(ctx context.Context, target string, opts adapters.DiagnosticOptions) (*model.Diagnostic, error) {
	rawURL := cleanTargetURL(target)

	diag := &model.Diagnostic{
		Target:    rawURL,
		Protocol:  "http",
		Timestamp: time.Now(),
		Status:    "passed",
		Metadata: map[string]interface{}{
			"url":       rawURL,
			"deep_mode": opts.Deep,
		},
	}

	startTotal := time.Now()

	// 1. URL Parsing
	c1Start := time.Now()
	parsedURL, err := url.Parse(rawURL)
	if err != nil || parsedURL.Host == "" {
		diag.Status = "failed"
		diag.FailedAt = "url_parse"
		diag.Checks = append(diag.Checks, model.Check{
			Name:        "URL Parsing",
			Stage:       "parse",
			Status:      model.StatusFailed,
			Duration:    time.Since(c1Start),
			DurationStr: time.Since(c1Start).String(),
			Error:       fmt.Sprintf("Invalid URL syntax: %v", err),
			Evidence:    map[string]interface{}{"raw_target": rawURL},
		})
		diag.Failure = &model.Failure{
			Stage:  "url_parse",
			Check:  "URL Parsing",
			Reason: fmt.Sprintf("Malformed URL: %v", err),
		}
		diag.TotalElapsed = time.Since(startTotal).String()
		return diag, nil
	}

	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https"
	}

	scheme := parsedURL.Scheme
	hostOnly := parsedURL.Hostname()
	portStr := parsedURL.Port()
	port := 80
	if scheme == "https" {
		port = 443
	}
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}

	diag.Checks = append(diag.Checks, model.Check{
		Name:        "URL Parsing",
		Stage:       "parse",
		Status:      model.StatusPassed,
		Duration:    time.Since(c1Start),
		DurationStr: time.Since(c1Start).String(),
		Summary:     fmt.Sprintf("%s :// %s%s (Port %d)", scheme, hostOnly, parsedURL.Path, port),
		Evidence: map[string]interface{}{
			"scheme": scheme,
			"host":   hostOnly,
			"path":   parsedURL.Path,
			"port":   port,
		},
	})

	// 2. DNS Resolution
	c2Start := time.Now()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, hostOnly)
	c2Dur := time.Since(c2Start)
	if err != nil {
		diag.Status = "failed"
		diag.FailedAt = "dns"
		diag.Checks = append(diag.Checks, model.Check{
			Name:        "DNS Resolution",
			Stage:       "dns",
			Status:      model.StatusFailed,
			Duration:    c2Dur,
			DurationStr: c2Dur.String(),
			Error:       err.Error(),
			Evidence:    map[string]interface{}{"host": hostOnly},
		})
		diag.Failure = &model.Failure{
			Stage:  "dns",
			Check:  "DNS Resolution",
			Reason: fmt.Sprintf("Failed to resolve domain %s: %v", hostOnly, err),
			Evidence: map[string]interface{}{
				"host": hostOnly,
				"err":  err.Error(),
			},
		}
		diag.TotalElapsed = time.Since(startTotal).String()
		return diag, nil
	}

	resolvedIP := ips[0].IP.String()
	diag.Checks = append(diag.Checks, model.Check{
		Name:        "DNS Resolution",
		Stage:       "dns",
		Status:      model.StatusPassed,
		Duration:    c2Dur,
		DurationStr: c2Dur.String(),
		Summary:     fmt.Sprintf("Resolved %s -> %s", hostOnly, resolvedIP),
		Evidence: map[string]interface{}{
			"host": hostOnly,
			"ip":   resolvedIP,
		},
	})

	// 3. TCP Connect
	c3Start := time.Now()
	targetAddr := net.JoinHostPort(resolvedIP, strconv.Itoa(port))
	dialer := net.Dialer{Timeout: 4 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	c3Dur := time.Since(c3Start)

	if err != nil {
		diag.Status = "failed"
		diag.FailedAt = "tcp"
		errStr := err.Error()
		evidence := map[string]interface{}{
			"host":        hostOnly,
			"ip":          resolvedIP,
			"port":        port,
			"destination": targetAddr,
			"error":       errStr,
		}

		reason := fmt.Sprintf("TCP connect to %s failed", targetAddr)
		if strings.Contains(errStr, "connection refused") {
			reason = fmt.Sprintf("Connection refused on port %d (No web server running or port closed)", port)
			evidence["tcp_status"] = "ECONNREFUSED"
		} else if strings.Contains(errStr, "i/o timeout") || strings.Contains(errStr, "deadline exceeded") {
			reason = fmt.Sprintf("TCP connect timed out on port %d (Firewall dropping packets or server unresponsive)", port)
			evidence["tcp_status"] = "ETIMEDOUT"
		}

		diag.Checks = append(diag.Checks, model.Check{
			Name:        fmt.Sprintf("TCP Connect :%d", port),
			Stage:       "tcp",
			Status:      model.StatusFailed,
			Duration:    c3Dur,
			DurationStr: c3Dur.String(),
			Error:       errStr,
			Evidence:    evidence,
		})

		diag.Failure = &model.Failure{
			Stage:    "tcp",
			Check:    fmt.Sprintf("TCP Connect :%d", port),
			Reason:   reason,
			Evidence: evidence,
		}

		diag.TotalElapsed = time.Since(startTotal).String()
		return diag, nil
	}
	rawConn.Close()

	diag.Checks = append(diag.Checks, model.Check{
		Name:        fmt.Sprintf("TCP Connect :%d", port),
		Stage:       "tcp",
		Status:      model.StatusPassed,
		Duration:    c3Dur,
		DurationStr: c3Dur.String(),
		Summary:     fmt.Sprintf("Connected in %v", c3Dur),
		Evidence: map[string]interface{}{
			"rtt": c3Dur.String(),
		},
	})

	// 4. TLS Handshake (if HTTPS)
	if scheme == "https" {
		c4Start := time.Now()
		tlsDialer := &net.Dialer{Timeout: 4 * time.Second}
		tlsConn, err := tls.DialWithDialer(tlsDialer, "tcp", targetAddr, &tls.Config{
			ServerName: hostOnly,
		})
		c4Dur := time.Since(c4Start)

		if err != nil {
			diag.Status = "failed"
			diag.FailedAt = "tls"
			errStr := err.Error()
			evidence := map[string]interface{}{
				"host":  hostOnly,
				"port":  port,
				"error": errStr,
			}

			reason := "TLS handshake failed"
			if strings.Contains(errStr, "expired") {
				reason = "SSL/TLS certificate has expired"
				evidence["issue"] = "CERT_EXPIRED"
			} else if strings.Contains(errStr, "unknown authority") {
				reason = "Untrusted SSL/TLS certificate authority (self-signed or missing intermediate cert)"
				evidence["issue"] = "UNTRUSTED_AUTHORITY"
			} else if strings.Contains(errStr, "certificate is not valid") {
				reason = "Certificate hostname mismatch (SAN does not match requested host)"
				evidence["issue"] = "HOSTNAME_MISMATCH"
			}

			diag.Checks = append(diag.Checks, model.Check{
				Name:        "TLS Handshake",
				Stage:       "tls",
				Status:      model.StatusFailed,
				Duration:    c4Dur,
				DurationStr: c4Dur.String(),
				Error:       errStr,
				Evidence:    evidence,
			})

			diag.Failure = &model.Failure{
				Stage:    "tls",
				Check:    "TLS Handshake",
				Reason:   reason,
				Evidence: evidence,
			}

			diag.TotalElapsed = time.Since(startTotal).String()
			return diag, nil
		}

		connState := tlsConn.ConnectionState()
		tlsConn.Close()

		diag.Checks = append(diag.Checks, model.Check{
			Name:        "TLS Handshake",
			Stage:       "tls",
			Status:      model.StatusPassed,
			Duration:    c4Dur,
			DurationStr: c4Dur.String(),
			Summary:     fmt.Sprintf("TLS negotiated with %s", hostOnly),
			Evidence: map[string]interface{}{
				"alpn":         connState.NegotiatedProtocol,
				"cipher_suite": tls.CipherSuiteName(connState.CipherSuite),
			},
		})
	}

	// 5. HTTP Request & Status Execution
	c5Start := time.Now()
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects (infinite redirect loop)")
			}
			return nil
		},
	}

	method := "GET"
	if opts.Method != "" {
		method = opts.Method
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		diag.Status = "failed"
		diag.FailedAt = "http_request_init"
		diag.Failure = &model.Failure{
			Stage:  "http_request_init",
			Check:  "HTTP Request Creation",
			Reason: err.Error(),
		}
		diag.TotalElapsed = time.Since(startTotal).String()
		return diag, nil
	}

	req.Header.Set("User-Agent", "why/1.0 (+https://github.com/kavix/why)")
	for _, h := range opts.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	resp, err := client.Do(req)
	c5Dur := time.Since(c5Start)

	if err != nil {
		diag.Status = "failed"
		diag.FailedAt = "http_request"
		diag.Checks = append(diag.Checks, model.Check{
			Name:        fmt.Sprintf("HTTP %s Request", method),
			Stage:       "http",
			Status:      model.StatusFailed,
			Duration:    c5Dur,
			DurationStr: c5Dur.String(),
			Error:       err.Error(),
		})

		diag.Failure = &model.Failure{
			Stage:  "http_request",
			Check:  fmt.Sprintf("HTTP %s Request", method),
			Reason: fmt.Sprintf("HTTP request failed: %v", err),
		}

		diag.TotalElapsed = time.Since(startTotal).String()
		return diag, nil
	}
	defer resp.Body.Close()

	// Read small snippet of body for error insight
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	bodySnippet := string(bodyBytes)

	headersMap := make(map[string]string)
	for k, v := range resp.Header {
		headersMap[k] = strings.Join(v, ", ")
	}

	httpEvidence := map[string]interface{}{
		"status_code":           resp.StatusCode,
		"status":                resp.Status,
		"proto":                 resp.Proto,
		"content_type":          resp.Header.Get("Content-Type"),
		"server":                resp.Header.Get("Server"),
		"body_snippet":          truncateSnippet(bodySnippet, 200),
		"method":                method,
		"url":                   rawURL,
		"authorization_present": req.Header.Get("Authorization") != "",
		"request_headers":       sanitizeHeaders(opts.Headers),
	}

	if resp.Header.Get("WWW-Authenticate") != "" {
		httpEvidence["www_authenticate"] = resp.Header.Get("WWW-Authenticate")
	}

	// Determine status: 4xx and 5xx are failures
	if resp.StatusCode >= 400 {
		diag.Status = "failed"
		diag.FailedAt = "http_response"

		diag.Checks = append(diag.Checks, model.Check{
			Name:        fmt.Sprintf("HTTP %s %s", method, parsedURL.Path),
			Stage:       "http",
			Status:      model.StatusFailed,
			Duration:    c5Dur,
			DurationStr: c5Dur.String(),
			Summary:     fmt.Sprintf("Status %s (%s)", resp.Status, resp.Proto),
			Error:       fmt.Sprintf("HTTP Error %d: %s", resp.StatusCode, resp.Status),
			Evidence:    httpEvidence,
		})

		diag.Failure = &model.Failure{
			Stage:    "http_response",
			Check:    fmt.Sprintf("HTTP %s %s", method, parsedURL.Path),
			Reason:   fmt.Sprintf("Server returned error status %d (%s)", resp.StatusCode, http.StatusText(resp.StatusCode)),
			Evidence: httpEvidence,
		}
	} else {
		diag.Checks = append(diag.Checks, model.Check{
			Name:        fmt.Sprintf("HTTP %s %s", method, parsedURL.Path),
			Stage:       "http",
			Status:      model.StatusPassed,
			Duration:    c5Dur,
			DurationStr: c5Dur.String(),
			Summary:     fmt.Sprintf("Status %d OK (%v)", resp.StatusCode, c5Dur),
			Evidence:    httpEvidence,
		})
	}

	diag.TotalElapsed = time.Since(startTotal).String()
	return diag, nil
}

func cleanTargetURL(target string) string {
	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(target, "curl ")
	target = strings.TrimPrefix(target, "http ")
	target = strings.TrimPrefix(target, "https ")
	target = strings.Trim(target, `"'`)
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}
	return target
}

func truncateSnippet(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// redactedMask reemplaza el valor de cualquier header sensible.
const redactedMask = "****************"

// sensitiveHeaders lista (en minúsculas) los headers cuyo valor nunca debe
// aparecer en la evidencia, en la salida JSON ni en los logs de CI.
var sensitiveHeaders = map[string]struct{}{
	"authorization":       {},
	"proxy-authorization": {},
	"cookie":              {},
	"set-cookie":          {},
	"x-api-key":           {},
	"token":               {},
}

// isSensitiveHeader indica si el nombre de header corresponde a uno sensible,
// sin distinguir mayúsculas de minúsculas.
func isSensitiveHeader(name string) bool {
	_, ok := sensitiveHeaders[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

// maskHeaderValue enmascara el valor de un header sensible. En Authorization y
// Proxy-Authorization conserva el esquema (Bearer, Basic, ...) para que el
// diagnóstico siga siendo útil sin exponer la credencial.
func maskHeaderValue(name, value string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "authorization" || lower == "proxy-authorization" {
		if fields := strings.Fields(value); len(fields) >= 2 {
			return fields[0] + " " + redactedMask
		}
	}
	return redactedMask
}

// sanitizeHeaders devuelve una copia de los headers en formato "Nombre: valor"
// con los valores sensibles enmascarados. No modifica el slice original.
// Las entradas sin ":" no son headers válidos y podrían ser un secreto pegado
// por error, por lo que se ocultan por completo.
func sanitizeHeaders(headers []string) []string {
	out := make([]string, 0, len(headers))
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			out = append(out, redactedMask)
			continue
		}
		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if isSensitiveHeader(name) {
			value = maskHeaderValue(name, value)
		}
		out = append(out, name+": "+value)
	}
	return out
}
