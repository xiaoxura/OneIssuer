package httpserver

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	logoutdomain "github.com/oneissuer/oneissuer/internal/logout"
	"github.com/oneissuer/oneissuer/internal/oidc"
	"github.com/oneissuer/oneissuer/internal/session"
)

const maxLogoutRequestBytes = 8 << 10

func (a *applicationHandler) handleRPLogoutRequest(writer http.ResponseWriter, request *http.Request) {
	setLogoutHeaders(writer.Header(), "no-referrer")
	if request.Method != http.MethodGet && request.Method != http.MethodPost {
		methodNotAllowed(writer, request, http.MethodGet, http.MethodPost)
		return
	}
	parsed, err := parseRPLogoutHTTPRequest(writer, request)
	if err != nil {
		a.renderLogoutResult(writer, request, http.StatusBadRequest, "invalid")
		return
	}
	operationCtx, cancel := operationContext(request)
	defer cancel()
	issued, err := a.logout.Start(operationCtx, logoutdomain.StartInput{
		IDTokenHint: parsed.IDTokenHint, ClientID: parsed.ClientID, LogoutHint: parsed.LogoutHint,
		PostLogoutRedirectURI: parsed.PostLogoutRedirectURI, State: parsed.State,
		UILocales: parsed.UILocales, Now: a.now().UTC(),
	})
	if err != nil {
		a.renderLogoutResult(writer, request, http.StatusInternalServerError, "unavailable")
		return
	}
	a.logoutCookies.Set(writer, issued.LookupToken)
	writer.Header().Set("Location", oidc.LogoutConfirmPath)
	writer.WriteHeader(http.StatusSeeOther)
}

func (a *applicationHandler) handleRPLogoutConfirmation(writer http.ResponseWriter, request *http.Request) {
	setLogoutHeaders(writer.Header(), "same-origin")
	switch request.Method {
	case http.MethodGet:
		a.getRPLogoutConfirmation(writer, request)
	case http.MethodPost:
		a.postRPLogoutConfirmation(writer, request)
	default:
		methodNotAllowed(writer, request, http.MethodGet, http.MethodPost)
	}
}

func (a *applicationHandler) getRPLogoutConfirmation(writer http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" || request.URL.ForceQuery || requestHasBody(writer, request) {
		a.logoutCookies.Clear(writer)
		a.renderLogoutResult(writer, request, http.StatusBadRequest, "invalid")
		return
	}
	lookup := a.logoutCookies.Token(request)
	if lookup == "" {
		a.logoutCookies.Clear(writer)
		a.renderLogoutResult(writer, request, http.StatusOK, "unavailable")
		return
	}
	operationCtx, cancel := operationContext(request)
	defer cancel()
	principal, err := a.authenticate(request.WithContext(operationCtx))
	if err != nil {
		if errors.Is(err, session.ErrUnauthenticated) {
			a.logoutCookies.Clear(writer)
			a.renderLogoutResult(writer, request, http.StatusOK, "already_signed_out")
			return
		}
		a.renderLogoutResult(writer, request, http.StatusInternalServerError, "unavailable")
		return
	}
	bound, err := a.logout.Bind(operationCtx, lookup, principal, a.now().UTC())
	if err != nil {
		switch {
		case errors.Is(err, logoutdomain.ErrNotFound):
			a.logoutCookies.Clear(writer)
			a.renderLogoutResult(writer, request, http.StatusBadRequest, "unavailable")
		case errors.Is(err, logoutdomain.ErrCapacity):
			writer.Header().Set("Retry-After", "1")
			a.renderLogoutResult(writer, request, http.StatusTooManyRequests, "unavailable")
		default:
			a.renderLogoutResult(writer, request, http.StatusInternalServerError, "unavailable")
		}
		return
	}
	setFormActionPolicy(writer.Header(), bound.PostLogoutRedirectURI)
	a.renderLogoutConfirmation(writer, request, bound.CSRFProof)
}

func (a *applicationHandler) postRPLogoutConfirmation(writer http.ResponseWriter, request *http.Request) {
	if !a.strictSameOrigin(request) {
		a.logoutCookies.Clear(writer)
		a.renderLogoutResult(writer, request, http.StatusForbidden, "invalid")
		return
	}
	csrfProof, decision, err := parseLogoutConfirmationForm(writer, request)
	if err != nil {
		a.logoutCookies.Clear(writer)
		a.renderLogoutResult(writer, request, http.StatusBadRequest, "invalid")
		return
	}
	lookup := a.logoutCookies.Token(request)
	if lookup == "" {
		a.logoutCookies.Clear(writer)
		a.renderLogoutResult(writer, request, http.StatusBadRequest, "unavailable")
		return
	}
	operationCtx, cancel := operationContext(request)
	defer cancel()
	principal, err := a.authenticate(request.WithContext(operationCtx))
	if err != nil {
		if errors.Is(err, session.ErrUnauthenticated) {
			a.logoutCookies.Clear(writer)
			a.renderLogoutResult(writer, request, http.StatusBadRequest, "unavailable")
			return
		}
		a.renderLogoutResult(writer, request, http.StatusInternalServerError, "unavailable")
		return
	}
	completion, err := a.logout.Complete(
		operationCtx, lookup, csrfProof, logoutdomain.Decision(decision), principal,
		RequestID(request.Context()), a.now().UTC(),
	)
	if err != nil {
		switch {
		case errors.Is(err, logoutdomain.ErrCSRF):
			a.logoutCookies.Clear(writer)
			a.renderLogoutResult(writer, request, http.StatusForbidden, "unavailable")
		case errors.Is(err, logoutdomain.ErrNotFound):
			a.logoutCookies.Clear(writer)
			a.renderLogoutResult(writer, request, http.StatusBadRequest, "unavailable")
		default:
			a.renderLogoutResult(writer, request, http.StatusInternalServerError, "unavailable")
		}
		return
	}
	a.logoutCookies.Clear(writer)
	if !completion.Confirmed {
		a.renderLogoutResult(writer, request, http.StatusOK, "canceled")
		return
	}
	// Authority and Audit are committed before either cookie is cleared or any
	// RP redirect is delivered.
	a.cookies.ClearAuthenticated(writer)
	if completion.Location != "" {
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("Location", completion.Location)
		writer.WriteHeader(http.StatusSeeOther)
		return
	}
	a.renderLogoutResult(writer, request, http.StatusOK, "confirmed")
}

func parseRPLogoutHTTPRequest(writer http.ResponseWriter, request *http.Request) (oidc.LogoutRequest, error) {
	if len(request.RequestURI) > maxLogoutRequestBytes {
		return oidc.LogoutRequest{}, oidc.ErrInvalidLogoutRequest
	}
	var values url.Values
	switch request.Method {
	case http.MethodGet:
		if requestHasBody(writer, request) {
			return oidc.LogoutRequest{}, oidc.ErrInvalidLogoutRequest
		}
		var err error
		values, err = url.ParseQuery(request.URL.RawQuery)
		if err != nil {
			return oidc.LogoutRequest{}, oidc.ErrInvalidLogoutRequest
		}
	case http.MethodPost:
		if request.URL.RawQuery != "" || request.URL.ForceQuery || len(request.Header.Values("Content-Type")) != 1 {
			return oidc.LogoutRequest{}, oidc.ErrInvalidLogoutRequest
		}
		mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || !strings.EqualFold(mediaType, "application/x-www-form-urlencoded") || len(parameters) != 0 || request.ContentLength > maxLogoutRequestBytes {
			return oidc.LogoutRequest{}, oidc.ErrInvalidLogoutRequest
		}
		request.Body = http.MaxBytesReader(writer, request.Body, maxLogoutRequestBytes)
		encoded, err := io.ReadAll(request.Body)
		if err != nil || !utf8.Valid(encoded) {
			return oidc.LogoutRequest{}, oidc.ErrInvalidLogoutRequest
		}
		values, err = url.ParseQuery(string(encoded))
		if err != nil {
			return oidc.LogoutRequest{}, oidc.ErrInvalidLogoutRequest
		}
	default:
		return oidc.LogoutRequest{}, oidc.ErrInvalidLogoutRequest
	}
	return oidc.ParseLogoutRequest(values)
}

func parseLogoutConfirmationForm(writer http.ResponseWriter, request *http.Request) (string, string, error) {
	if request.URL.RawQuery != "" || request.URL.ForceQuery || len(request.Header.Values("Content-Type")) != 1 || request.ContentLength > maxLogoutRequestBytes {
		return "", "", errors.New("invalid logout confirmation")
	}
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "application/x-www-form-urlencoded") || len(parameters) != 0 {
		return "", "", errors.New("invalid logout confirmation content type")
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxLogoutRequestBytes)
	encoded, err := io.ReadAll(request.Body)
	if err != nil || len(encoded) == 0 || !utf8.Valid(encoded) {
		return "", "", errors.New("invalid logout confirmation body")
	}
	values, err := url.ParseQuery(string(encoded))
	if err != nil || len(values) != 2 || len(values["csrf_token"]) != 1 || len(values["decision"]) != 1 {
		return "", "", errors.New("invalid logout confirmation form")
	}
	for key, entries := range values {
		if (key != "csrf_token" && key != "decision") || len(entries) != 1 || entries[0] == "" ||
			!utf8.ValidString(entries[0]) || strings.ContainsRune(entries[0], '\x00') {
			return "", "", errors.New("invalid logout confirmation field")
		}
	}
	decision := values.Get("decision")
	if decision != string(logoutdomain.DecisionConfirm) && decision != string(logoutdomain.DecisionCancel) {
		return "", "", errors.New("invalid logout confirmation decision")
	}
	return values.Get("csrf_token"), decision, nil
}

func requestHasBody(writer http.ResponseWriter, request *http.Request) bool {
	if request.ContentLength > 0 {
		return true
	}
	if request.Body == nil || request.Body == http.NoBody {
		return false
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 1)
	value := make([]byte, 1)
	count, _ := request.Body.Read(value)
	return count != 0
}

func (a *applicationHandler) strictSameOrigin(request *http.Request) bool {
	if len(request.Header.Values("Origin")) > 1 || len(request.Header.Values("Referer")) > 1 {
		return false
	}
	origin := strings.TrimSpace(request.Header.Get("Origin"))
	referer := strings.TrimSpace(request.Header.Get("Referer"))
	if origin == "" && referer == "" {
		return false
	}
	if origin != "" && !a.matchesIssuerOrigin(origin, false) {
		return false
	}
	return referer == "" || a.matchesIssuerOrigin(referer, true)
}

func (a *applicationHandler) matchesIssuerOrigin(raw string, allowResourcePath bool) bool {
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.User != nil || parsed.Opaque != "" || parsed.Fragment != "" {
		return false
	}
	if !allowResourcePath && ((parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.ForceQuery) {
		return false
	}
	return strings.EqualFold(parsed.Scheme, a.issuer.Scheme) && strings.EqualFold(parsed.Host, a.issuer.Host)
}

func setLogoutHeaders(header http.Header, referrerPolicy string) {
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
	header.Set("Referrer-Policy", referrerPolicy)
}

type logoutConfirmationPageData struct {
	Lang         string
	Title        string
	Message      string
	CSRFToken    string
	ConfirmLabel string
	CancelLabel  string
}

type logoutResultPageData struct {
	Lang       string
	Title      string
	Message    string
	ResultCode string
}

func (a *applicationHandler) renderLogoutConfirmation(writer http.ResponseWriter, request *http.Request, csrfProof string) {
	lang := preferredLanguage(request)
	data := logoutConfirmationPageData{
		Lang: lang, Title: "Sign out", Message: "Confirm that you want to sign out of OneIssuer.",
		CSRFToken: csrfProof, ConfirmLabel: "Sign out", CancelLabel: "Cancel",
	}
	if lang == "zh-CN" {
		data.Title, data.Message, data.ConfirmLabel, data.CancelLabel = "退出登录", "请确认是否退出 OneIssuer。", "退出", "取消"
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_ = a.templates.ExecuteTemplate(writer, "logout_confirm.html", data)
}

func (a *applicationHandler) renderLogoutResult(writer http.ResponseWriter, request *http.Request, status int, result string) {
	lang := preferredLanguage(request)
	messages := map[string]string{
		"confirmed": "You have signed out of OneIssuer.", "canceled": "You are still signed in.",
		"already_signed_out": "There is no active OneIssuer session to sign out.",
		"invalid":            "The logout request could not be continued.", "unavailable": "The logout confirmation is no longer available.",
	}
	message := messages[result]
	if message == "" {
		result, message = "unavailable", messages["unavailable"]
	}
	title := "Sign out"
	if lang == "zh-CN" {
		title = "退出登录"
		chinese := map[string]string{
			"confirmed": "你已退出 OneIssuer。", "canceled": "你仍处于登录状态。",
			"already_signed_out": "当前没有可退出的 OneIssuer 会话。",
			"invalid":            "无法继续此退出请求。", "unavailable": "此退出确认已不可用。",
		}
		message = chinese[result]
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(status)
	_ = a.templates.ExecuteTemplate(writer, "logout_result.html", logoutResultPageData{
		Lang: lang, Title: title, Message: message, ResultCode: result,
	})
}
