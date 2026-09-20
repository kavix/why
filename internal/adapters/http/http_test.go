package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kavix/why/internal/adapters"
)

var testSecrets = []string{
	"abc123SECRETbearer",
	"dXNlcjpwYXNzd29yZA==",
	"proxySECRETvalue",
	"SECRETcookieValue",
	"SECRETsetCookie",
	"SUPERSECRETAPIKEY",
	"SECRETtokenValue",
}

func TestSanitizeHeaders_RedactsSensitiveValues(t *testing.T) {
	in := []string{
		"Authorization: Bearer abc123SECRETbearer",
		"Authorization: Basic dXNlcjpwYXNzd29yZA==",
		"Proxy-Authorization: Basic proxySECRETvalue",
		"Cookie: session=SECRETcookieValue; theme=dark",
		"Set-Cookie: id=SECRETsetCookie; HttpOnly",
		"X-Api-Key: SUPERSECRETAPIKEY",
		"Token: SECRETtokenValue",
		"Accept: application/json",
	}

	out := sanitizeHeaders(in)

	if len(out) != len(in) {
		t.Fatalf("se esperaban %d headers, se obtuvieron %d", len(in), len(out))
	}

	joined := strings.Join(out, "\n")
	for _, secret := range testSecrets {
		if strings.Contains(joined, secret) {
			t.Errorf("el secreto %q se filtró en la salida:\n%s", secret, joined)
		}
	}

	expected := []string{
		"Authorization: Bearer " + redactedMask,
		"Authorization: Basic " + redactedMask,
		"Proxy-Authorization: Basic " + redactedMask,
		"Cookie: " + redactedMask,
		"Set-Cookie: " + redactedMask,
		"X-Api-Key: " + redactedMask,
		"Token: " + redactedMask,
		"Accept: application/json",
	}
	for i, want := range expected {
		if out[i] != want {
			t.Errorf("header %d: se esperaba %q, se obtuvo %q", i, want, out[i])
		}
	}
}

func TestSanitizeHeaders_CaseInsensitiveNames(t *testing.T) {
	out := sanitizeHeaders([]string{
		"AUTHORIZATION:Bearer secretUPPER",
		"x-api-key:secretlower",
		"  CoOkIe :   secretMixed  ",
	})
	joined := strings.Join(out, "\n")
	for _, secret := range []string{"secretUPPER", "secretlower", "secretMixed"} {
		if strings.Contains(joined, secret) {
			t.Errorf("el secreto %q se filtró: %s", secret, joined)
		}
	}
}

func TestSanitizeHeaders_AuthorizationWithoutSchemeIsFullyMasked(t *testing.T) {
	out := sanitizeHeaders([]string{"Authorization: rawtokenwithoutscheme"})
	if out[0] != "Authorization: "+redactedMask {
		t.Errorf("se obtuvo %q", out[0])
	}
}

func TestSanitizeHeaders_MalformedEntriesAreHidden(t *testing.T) {
	out := sanitizeHeaders([]string{"Bearer pegado-sin-dos-puntos"})
	if strings.Contains(out[0], "pegado") {
		t.Errorf("una entrada malformada se filtró: %q", out[0])
	}
}

func TestSanitizeHeaders_DoesNotMutateInput(t *testing.T) {
	in := []string{"Authorization: Bearer keepme"}
	_ = sanitizeHeaders(in)
	if in[0] != "Authorization: Bearer keepme" {
		t.Errorf("el slice original fue modificado: %q", in[0])
	}
}

func TestSanitizeHeaders_EmptyInput(t *testing.T) {
	if out := sanitizeHeaders(nil); len(out) != 0 {
		t.Errorf("se esperaba slice vacío, se obtuvo %v", out)
	}
}

func TestDiagnose_EvidenceNeverContainsRawSecrets(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	headers := []string{
		"Authorization: Bearer abc123SECRETbearer",
		"Cookie: session=SECRETcookieValue",
		"X-Api-Key: SUPERSECRETAPIKEY",
		"Token: SECRETtokenValue",
		"Accept: application/json",
	}

	a := New()
	diag, err := a.Diagnose(context.Background(), srv.URL, adapters.DiagnosticOptions{Headers: headers})
	if err != nil {
		t.Fatalf("Diagnose devolvió error: %v", err)
	}

	// La petición real sí debe llevar el valor original: no hay regresión funcional.
	if gotAuth != "Bearer abc123SECRETbearer" {
		t.Errorf("el servidor recibió Authorization %q; el header real debe enviarse sin modificar", gotAuth)
	}

	if diag.Status != "failed" || diag.Failure == nil {
		t.Fatalf("se esperaba un diagnóstico fallido por 401, se obtuvo status=%q", diag.Status)
	}

	if present, _ := diag.Failure.Evidence["authorization_present"].(bool); !present {
		t.Errorf("authorization_present debería ser true: %v", diag.Failure.Evidence)
	}
	if _, legacy := diag.Failure.Evidence["authorization"]; legacy {
		t.Errorf("la clave antigua 'authorization' no debería existir")
	}

	raw, err := json.Marshal(diag)
	if err != nil {
		t.Fatalf("no se pudo serializar el diagnóstico: %v", err)
	}
	for _, secret := range testSecrets {
		if strings.Contains(string(raw), secret) {
			t.Errorf("el secreto %q aparece en el JSON del diagnóstico", secret)
		}
	}

	shown, _ := diag.Failure.Evidence["request_headers"].([]string)
	if len(shown) != len(headers) {
		t.Fatalf("request_headers debería tener %d entradas, tiene %d", len(headers), len(shown))
	}
	if shown[0] != "Authorization: Bearer "+redactedMask {
		t.Errorf("Authorization enmascarado incorrectamente: %q", shown[0])
	}
	if shown[4] != "Accept: application/json" {
		t.Errorf("un header no sensible fue alterado: %q", shown[4])
	}
}

func TestDiagnose_AuthorizationPresentFalseWhenAbsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	diag, err := New().Diagnose(context.Background(), srv.URL, adapters.DiagnosticOptions{})
	if err != nil {
		t.Fatalf("Diagnose devolvió error: %v", err)
	}
	if diag.Failure == nil {
		t.Fatalf("se esperaba un fallo por 403")
	}
	if present, ok := diag.Failure.Evidence["authorization_present"].(bool); !ok || present {
		t.Errorf("authorization_present debería ser false: %v", diag.Failure.Evidence)
	}
}
