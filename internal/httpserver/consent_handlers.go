package httpserver

import (
	"context"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/authflow"
	"github.com/oneissuer/oneissuer/internal/authorization"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/consent"
	"github.com/oneissuer/oneissuer/internal/oidc"
	"github.com/oneissuer/oneissuer/internal/session"
)

const maxConsentBodyBytes = 8 << 10

type consentScopeData struct {
	Name, Description, Status string
}

type consentPageData struct {
	Lang, Title, Intro, ClientName, TransactionToken, CSRFToken string
	ApproveLabel, DenyLabel                                     string
	Scopes                                                      []consentScopeData
}

type consentText struct {
	Title, Intro, Approve, Deny, NewStatus, ExistingStatus string
	Scopes                                                 map[string][2]string
}

var consentTranslations = map[string]consentText{
	"en": {
		Title: "Authorize application", Intro: "This application is requesting access to your account.",
		Approve: "Allow", Deny: "Deny", NewStatus: "New request", ExistingStatus: "Previously granted",
		Scopes: map[string][2]string{
			"openid":         {"Basic identity", "Confirm your stable account identifier."},
			"profile":        {"Profile", "Read your display name and username."},
			"email":          {"Email", "Read your email address and verification status."},
			"offline_access": {"Offline access", "Keep long-lived access when you are not actively using this browser session."},
		},
	},
	"zh-CN": {
		Title: "授权应用", Intro: "此应用正在请求访问你的账户信息。",
		Approve: "允许", Deny: "拒绝", NewStatus: "本次新增", ExistingStatus: "已授予",
		Scopes: map[string][2]string{
			"openid":         {"基本身份", "确认你的稳定账户标识。"},
			"profile":        {"个人资料", "读取你的显示名称和用户名。"},
			"email":          {"邮箱", "读取你的邮箱地址和验证状态。"},
			"offline_access": {"离线访问", "即使你当前未使用此浏览器会话，仍允许应用维持长期访问。"},
		},
	},
}

func (a *applicationHandler) getConsent(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	if !validConsentQuery(query) {
		a.renderErrorPage(writer, request, http.StatusBadRequest, "invalid_authentication_flow")
		return
	}
	token := query.Get("transaction")
	transaction, err := a.transactions.Resolve(request.Context(), token, a.now().UTC())
	if err != nil || transaction.Kind != authflow.KindAuthorization {
		a.renderErrorPage(writer, request, http.StatusBadRequest, "invalid_authentication_flow")
		return
	}
	principal, ok := a.consentPrincipal(writer, request, token, transaction)
	if !ok {
		return
	}
	clientValue, evaluation, err := a.evaluateAuthorization(request.Context(), principal.User.ID, transaction)
	if err != nil {
		a.terminateAuthorization(writer, request, transaction, oidc.ErrorServerError, "client_disabled", &principal.User.ID)
		return
	}
	csrf, err := a.ensureCSRF(writer, request, &principal)
	if err != nil {
		a.terminateAuthorization(writer, request, transaction, oidc.ErrorServerError, "server_error", &principal.User.ID)
		return
	}
	a.renderConsent(writer, request, clientValue, transaction, evaluation, token, csrf)
}

func (a *applicationHandler) postConsent(writer http.ResponseWriter, request *http.Request) {
	if !a.sameOrigin(request) {
		a.renderErrorPage(writer, request, http.StatusForbidden, "csrf_failed")
		return
	}
	form, err := parseConsentForm(writer, request)
	if err != nil {
		a.renderErrorPage(writer, request, http.StatusBadRequest, "invalid_input")
		return
	}
	token := form.Get("transaction")
	transaction, err := a.transactions.Resolve(request.Context(), token, a.now().UTC())
	if err != nil || transaction.Kind != authflow.KindAuthorization {
		a.renderErrorPage(writer, request, http.StatusBadRequest, "invalid_authentication_flow")
		return
	}
	principal, ok := a.consentPrincipal(writer, request, token, transaction)
	if !ok {
		return
	}
	csrf := form.Get("csrf_token")
	if !sameClearToken(csrf, a.cookies.CSRFToken(request)) || a.sessions.ValidateCSRF(principal, csrf, a.now().UTC()) != nil {
		a.renderErrorPage(writer, request, http.StatusForbidden, "csrf_failed")
		return
	}
	if _, _, err := a.evaluateAuthorization(request.Context(), principal.User.ID, transaction); err != nil {
		a.terminateAuthorization(writer, request, transaction, oidc.ErrorServerError, "client_disabled", &principal.User.ID)
		return
	}

	switch form.Get("decision") {
	case "deny":
		err = a.authorization.Deny(request.Context(), transaction, principal.User.ID, RequestID(request.Context()), a.now().UTC())
		if err != nil {
			a.handleAuthorizationDecisionError(writer, request, transaction, principal.User.ID, err)
			return
		}
		a.writeAuthorizationError(writer, request, &oidc.AuthorizationError{
			Code: oidc.ErrorAccessDenied, HTTPStatus: http.StatusFound, SafeToRedirect: true,
			RedirectURI: transaction.RedirectURI, State: transaction.State,
		})
	case "approve":
		a.issueAuthorizationCode(writer, request, token, transaction, principal, true)
	default:
		a.renderErrorPage(writer, request, http.StatusBadRequest, "invalid_input")
	}
}

func (a *applicationHandler) consentPrincipal(writer http.ResponseWriter, request *http.Request, token string, transaction authflow.Transaction) (session.Principal, bool) {
	principal, err := a.sessions.Authenticate(request.Context(), a.cookies.SessionToken(request), a.now().UTC())
	if err != nil {
		if !errors.Is(err, session.ErrUnauthenticated) {
			a.terminateAuthorization(writer, request, transaction, oidc.ErrorServerError, "server_error", nil)
			return session.Principal{}, false
		}
		if transactionHasPrompt(transaction, "none") {
			a.terminateAuthorization(writer, request, transaction, oidc.ErrorLoginRequired, "login_required", nil)
			return session.Principal{}, false
		}
		if transactionHasPrompt(transaction, "create") {
			if !a.authn.CanRegister(request.Context(), transaction) {
				a.terminateAuthorization(writer, request, transaction, oidc.ErrorInteractionRequired, "interaction_required", nil)
				return session.Principal{}, false
			}
			a.redirectToBrowserFlow(writer, "/register", token)
			return session.Principal{}, false
		}
		a.redirectToBrowserFlow(writer, "/login", token)
		return session.Principal{}, false
	}
	if transactionHasPrompt(transaction, "create") && !principal.AuthenticatedAt.After(transaction.CreatedAt) {
		a.terminateAuthorization(writer, request, transaction, oidc.ErrorInteractionRequired, "interaction_required", &principal.User.ID)
		return session.Principal{}, false
	}
	if authorizationNeedsReauthentication(transaction, principal.AuthenticatedAt, a.now().UTC()) {
		if transactionHasPrompt(transaction, "none") {
			a.terminateAuthorization(writer, request, transaction, oidc.ErrorLoginRequired, "login_required", &principal.User.ID)
			return session.Principal{}, false
		}
		a.redirectToBrowserFlow(writer, "/login", token)
		return session.Principal{}, false
	}
	return principal, true
}

func (a *applicationHandler) evaluateAuthorization(ctx context.Context, userID uuid.UUID, transaction authflow.Transaction) (clientdomain.Client, consent.Evaluation, error) {
	if transaction.ClientID == nil || *transaction.ClientID == uuid.Nil {
		return clientdomain.Client{}, consent.Evaluation{}, authorization.ErrInvalid
	}
	clientValue, err := a.clients.GetActive(ctx, *transaction.ClientID)
	if err != nil || !a.clients.RedirectURIMatches(clientValue, transaction.RedirectURI) {
		return clientdomain.Client{}, consent.Evaluation{}, authorization.ErrInactive
	}
	evaluation, err := a.consents.Evaluate(ctx, userID, clientValue, transaction.Scopes)
	if err != nil {
		return clientdomain.Client{}, consent.Evaluation{}, err
	}
	return clientValue, evaluation, nil
}

func (a *applicationHandler) renderConsent(writer http.ResponseWriter, request *http.Request, clientValue clientdomain.Client, transaction authflow.Transaction, evaluation consent.Evaluation, token, csrf string) {
	lang := preferredLanguage(request)
	text := consentTranslations[lang]
	scopes := make([]consentScopeData, 0, len(transaction.Scopes))
	for _, scope := range []string{"openid", "profile", "email", "offline_access"} {
		if !slices.Contains(transaction.Scopes, scope) {
			continue
		}
		scopeText := text.Scopes[scope]
		status := text.NewStatus
		if slices.Contains(evaluation.AlreadyGranted, scope) {
			status = text.ExistingStatus
		}
		scopes = append(scopes, consentScopeData{Name: scopeText[0], Description: scopeText[1], Status: status})
	}
	setFormActionPolicy(writer.Header(), transaction.RedirectURI)
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)
	_ = a.templates.ExecuteTemplate(writer, "consent.html", consentPageData{
		Lang: lang, Title: text.Title, Intro: text.Intro, ClientName: clientValue.Name,
		TransactionToken: token, CSRFToken: csrf, ApproveLabel: text.Approve, DenyLabel: text.Deny, Scopes: scopes,
	})
}

func (a *applicationHandler) handleAuthorizationDecisionError(writer http.ResponseWriter, request *http.Request, transaction authflow.Transaction, userID uuid.UUID, err error) {
	switch {
	case errors.Is(err, authorization.ErrConsumed), errors.Is(err, authorization.ErrExpired), errors.Is(err, authorization.ErrNotFound), errors.Is(err, authorization.ErrInvalid):
		a.renderErrorPage(writer, request, http.StatusBadRequest, "invalid_authentication_flow")
	default:
		a.terminateAuthorization(writer, request, transaction, oidc.ErrorServerError, "server_error", &userID)
	}
}

func validConsentQuery(values url.Values) bool {
	for key := range values {
		if key != "transaction" && key != "lang" {
			return false
		}
	}
	return len(values["transaction"]) == 1 && values.Get("transaction") != "" && len(values["lang"]) <= 1
}

func parseConsentForm(writer http.ResponseWriter, request *http.Request) (url.Values, error) {
	if request.URL.RawQuery != "" || len(request.Header.Values("Content-Type")) != 1 {
		return nil, errors.New("invalid consent form")
	}
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" || len(parameters) != 0 {
		return nil, errors.New("invalid consent content type")
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxConsentBodyBytes)
	if err := request.ParseForm(); err != nil {
		return nil, errors.New("invalid consent form")
	}
	allowed := map[string]bool{"transaction": true, "csrf_token": true, "decision": true}
	if len(request.PostForm) != len(allowed) {
		return nil, errors.New("invalid consent fields")
	}
	for key, entries := range request.PostForm {
		if !allowed[key] || len(entries) != 1 || strings.TrimSpace(entries[0]) != entries[0] || entries[0] == "" {
			return nil, errors.New("invalid consent field")
		}
	}
	if decision := request.PostForm.Get("decision"); decision != "approve" && decision != "deny" {
		return nil, errors.New("invalid consent decision")
	}
	return request.PostForm, nil
}
