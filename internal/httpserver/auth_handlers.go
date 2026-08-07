package httpserver

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/oneissuer/oneissuer/internal/authflow"
	"github.com/oneissuer/oneissuer/internal/authn"
	"github.com/oneissuer/oneissuer/internal/identity"
	"github.com/oneissuer/oneissuer/internal/oidc"
	"github.com/oneissuer/oneissuer/internal/session"
)

type authPageData struct {
	Lang, Title, Action, CSRFToken, TransactionToken string
	ErrorCode, ErrorMessage                          string
	UsernameLabel, DisplayNameLabel, EmailLabel      string
	IdentifierLabel, PasswordLabel, SubmitLabel      string
	SwitchLabel, SwitchURL                           string
	Register                                         bool
}

type completePageData struct {
	Lang, Title, Greeting, DisplayName, CSRFToken, LogoutLabel string
}

type errorPageData struct {
	Lang, Title, ErrorCode, ErrorMessage, BackLabel string
}

type authText struct {
	LoginTitle, RegisterTitle, Identifier, Username, DisplayName, Email, Password string
	LoginSubmit, RegisterSubmit, ToLogin, ToRegister, CompleteTitle, Greeting     string
	Logout, ErrorTitle, Back                                                      string
}

var authTranslations = map[string]authText{
	"en": {
		LoginTitle: "Sign in", RegisterTitle: "Create account", Identifier: "Username or email",
		Username: "Username", DisplayName: "Display name", Email: "Email", Password: "Password",
		LoginSubmit: "Sign in", RegisterSubmit: "Create account", ToLogin: "Already registered? Sign in",
		ToRegister: "Create an account", CompleteTitle: "Authentication complete", Greeting: "Signed in as",
		Logout: "Sign out", ErrorTitle: "Request could not be completed", Back: "Back to sign in",
	},
	"zh-CN": {
		LoginTitle: "登录", RegisterTitle: "创建账户", Identifier: "用户名或邮箱",
		Username: "用户名", DisplayName: "显示名称", Email: "邮箱", Password: "密码",
		LoginSubmit: "登录", RegisterSubmit: "创建账户", ToLogin: "已有账户？去登录",
		ToRegister: "创建账户", CompleteTitle: "认证完成", Greeting: "当前登录用户",
		Logout: "退出登录", ErrorTitle: "无法完成请求", Back: "返回登录",
	},
}

// #nosec G101 -- these are public localization keys/messages, not credentials.
var errorTranslations = map[string]map[string]string{
	"en": {
		"invalid_credentials":         "The username/email or password is incorrect.",
		"registration_conflict":       "An account with these details cannot be created.",
		"invalid_input":               "Please check the submitted fields.",
		"csrf_failed":                 "The form expired or was opened in another browser session.",
		"invalid_authentication_flow": "The authentication flow expired or is invalid.",
		"registration_disabled":       "Self-service registration is not available.",
		"temporarily_unavailable":     "Authentication is temporarily busy. Please retry.",
		"internal_error":              "The request could not be completed.",
	},
	"zh-CN": {
		"invalid_credentials":         "用户名、邮箱或密码不正确。",
		"registration_conflict":       "无法使用这些信息创建账户。",
		"invalid_input":               "请检查提交的字段。",
		"csrf_failed":                 "表单已过期或来自其他浏览器会话。",
		"invalid_authentication_flow": "认证流程已过期或无效。",
		"registration_disabled":       "当前未开放自助注册。",
		"temporarily_unavailable":     "认证服务暂时繁忙，请重试。",
		"internal_error":              "暂时无法完成请求。",
	},
}

func (a *applicationHandler) getAuthForm(writer http.ResponseWriter, request *http.Request, mode authn.BeginMode) {
	if !validAuthQuery(request.URL.Query()) {
		a.renderErrorPage(writer, request, http.StatusBadRequest, "invalid_authentication_flow")
		return
	}
	result, err := a.authn.Begin(request.Context(), mode, request.URL.Query().Get("transaction"), RequestID(request.Context()), a.now().UTC())
	if err != nil {
		status, code, _ := authErrorStatus(err)
		a.renderErrorPage(writer, request, status, code)
		return
	}
	a.cookies.SetPreAuth(writer, result.PreAuth)
	a.renderAuthForm(writer, request, http.StatusOK, mode, result.PreAuth.CSRFToken, result.TransactionToken, "")
}

func (a *applicationHandler) postLogin(writer http.ResponseWriter, request *http.Request) {
	if !a.sameOrigin(request) {
		a.renderErrorPage(writer, request, http.StatusForbidden, "csrf_failed")
		return
	}
	form, err := parseAuthForm(writer, request, "csrf_token", "transaction", "identifier", "password")
	if err != nil {
		a.renderErrorPage(writer, request, http.StatusBadRequest, "invalid_input")
		return
	}
	issued, _, err := a.authn.Login(request.Context(), authn.LoginInput{
		PreAuthToken: a.cookies.PreAuthToken(request), CSRFToken: form.Get("csrf_token"),
		TransactionToken: form.Get("transaction"), Identifier: form.Get("identifier"), Password: form.Get("password"),
		ExistingSessionToken: a.cookies.SessionToken(request), UserAgent: request.UserAgent(), ClientIP: requestClientIP(request),
		RequestID: RequestID(request.Context()),
	}, a.now().UTC())
	if err != nil {
		status, code := browserError(err)
		if code == "csrf_failed" || code == "invalid_authentication_flow" || code == "internal_error" {
			a.renderErrorPage(writer, request, status, code)
			return
		}
		a.renderAuthForm(writer, request, status, authn.BeginLogin, form.Get("csrf_token"), form.Get("transaction"), code)
		return
	}
	a.cookies.SetAuthenticated(writer, issued)
	writer.Header().Set("Location", a.authenticationSuccessLocation(request, form.Get("transaction")))
	writer.WriteHeader(http.StatusSeeOther)
}

func (a *applicationHandler) postRegister(writer http.ResponseWriter, request *http.Request) {
	if !a.sameOrigin(request) {
		a.renderErrorPage(writer, request, http.StatusForbidden, "csrf_failed")
		return
	}
	form, err := parseAuthForm(writer, request, "csrf_token", "transaction", "username", "display_name", "email", "password")
	if err != nil {
		a.renderErrorPage(writer, request, http.StatusBadRequest, "invalid_input")
		return
	}
	issued, err := a.authn.Register(request.Context(), authn.RegisterInput{
		PreAuthToken: a.cookies.PreAuthToken(request), CSRFToken: form.Get("csrf_token"), TransactionToken: form.Get("transaction"),
		Account:              identity.CreateInput{Username: form.Get("username"), DisplayName: form.Get("display_name"), Email: form.Get("email"), Password: form.Get("password")},
		ExistingSessionToken: a.cookies.SessionToken(request),
		UserAgent:            request.UserAgent(), ClientIP: requestClientIP(request), RequestID: RequestID(request.Context()),
	}, a.now().UTC())
	if err != nil {
		status, code := browserError(err)
		if code == "csrf_failed" || code == "invalid_authentication_flow" || code == "registration_disabled" || code == "internal_error" {
			a.renderErrorPage(writer, request, status, code)
			return
		}
		a.renderAuthForm(writer, request, status, authn.BeginRegister, form.Get("csrf_token"), form.Get("transaction"), code)
		return
	}
	a.cookies.SetAuthenticated(writer, issued)
	writer.Header().Set("Location", a.authenticationSuccessLocation(request, form.Get("transaction")))
	writer.WriteHeader(http.StatusSeeOther)
}

func (a *applicationHandler) authenticationSuccessLocation(request *http.Request, transactionToken string) string {
	if a.transactions == nil || transactionToken == "" {
		return "/auth/complete"
	}
	transaction, err := a.transactions.Resolve(request.Context(), transactionToken, a.now().UTC())
	if err != nil || transaction.Kind != authflow.KindAuthorization {
		return "/auth/complete"
	}
	return (&url.URL{Path: oidc.AuthorizeContinuePath, RawQuery: url.Values{"transaction": {transactionToken}}.Encode()}).String()
}

func (a *applicationHandler) getComplete(writer http.ResponseWriter, request *http.Request) {
	principal, err := a.authenticate(request)
	if err != nil {
		a.cookies.ClearAuthenticated(writer)
		writer.Header().Set("Location", "/login")
		writer.WriteHeader(http.StatusSeeOther)
		return
	}
	csrf, err := a.ensureCSRF(writer, request, &principal)
	if err != nil {
		a.renderErrorPage(writer, request, http.StatusInternalServerError, "internal_error")
		return
	}
	lang := preferredLanguage(request)
	text := authTranslations[lang]
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_ = a.templates.ExecuteTemplate(writer, "complete.html", completePageData{
		Lang: lang, Title: text.CompleteTitle, Greeting: text.Greeting,
		DisplayName: principal.User.DisplayName, CSRFToken: csrf, LogoutLabel: text.Logout,
	})
}

func (a *applicationHandler) postLogout(writer http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" || request.URL.ForceQuery {
		a.renderErrorPage(writer, request, http.StatusBadRequest, "invalid_input")
		return
	}
	operationCtx, cancel := operationContext(request)
	defer cancel()
	request = request.WithContext(operationCtx)

	principal, err := a.authenticate(request)
	if err != nil {
		if errors.Is(err, session.ErrUnauthenticated) {
			a.cookies.ClearAuthenticated(writer)
			writer.Header().Set("Location", "/login")
			writer.WriteHeader(http.StatusSeeOther)
			return
		}
		a.renderErrorPage(writer, request, http.StatusInternalServerError, "internal_error")
		return
	}
	form, err := parseAuthForm(writer, request, "csrf_token")
	if err != nil || !sameClearToken(form.Get("csrf_token"), a.cookies.CSRFToken(request)) ||
		!a.requireStateChange(writer, request, principal, form.Get("csrf_token")) {
		if err != nil {
			a.renderErrorPage(writer, request, http.StatusBadRequest, "invalid_input")
		}
		return
	}
	err = a.sessions.Logout(operationCtx, principal, a.cookies.SessionToken(request), RequestID(request.Context()), a.now().UTC())
	if err != nil && !errors.Is(err, session.ErrNotFound) {
		a.renderErrorPage(writer, request, http.StatusInternalServerError, "internal_error")
		return
	}
	a.cookies.ClearAuthenticated(writer)
	writer.Header().Set("Location", "/login")
	writer.WriteHeader(http.StatusSeeOther)
}

func (a *applicationHandler) renderAuthForm(writer http.ResponseWriter, request *http.Request, status int, mode authn.BeginMode, csrf, transaction, errorCode string) {
	lang := preferredLanguage(request)
	text := authTranslations[lang]
	register := mode == authn.BeginRegister
	data := authPageData{
		Lang: lang, CSRFToken: csrf, TransactionToken: transaction, ErrorCode: errorCode,
		UsernameLabel: text.Username, DisplayNameLabel: text.DisplayName, EmailLabel: text.Email,
		IdentifierLabel: text.Identifier, PasswordLabel: text.Password, Register: register,
	}
	if errorCode != "" {
		data.ErrorMessage = translatedError(lang, errorCode)
	}
	escapedTransaction := url.QueryEscape(transaction)
	if register {
		data.Title, data.Action, data.SubmitLabel, data.SwitchLabel = text.RegisterTitle, "/register", text.RegisterSubmit, text.ToLogin
		allowSwitch := true
		if transaction != "" && a.transactions != nil {
			if flow, err := a.transactions.Resolve(request.Context(), transaction, a.now().UTC()); err == nil && flow.Kind == authflow.KindAuthorization && flow.PromptCreate {
				allowSwitch = false
			}
		}
		if allowSwitch {
			data.SwitchURL = "/login?transaction=" + escapedTransaction
		}
	} else {
		data.Title, data.Action, data.SubmitLabel, data.SwitchLabel = text.LoginTitle, "/login", text.LoginSubmit, text.ToRegister
		data.SwitchURL = "/register?transaction=" + escapedTransaction
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(status)
	_ = a.templates.ExecuteTemplate(writer, "auth.html", data)
}

func (a *applicationHandler) renderErrorPage(writer http.ResponseWriter, request *http.Request, status int, code string) {
	lang := preferredLanguage(request)
	text := authTranslations[lang]
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(status)
	_ = a.templates.ExecuteTemplate(writer, "error.html", errorPageData{
		Lang: lang, Title: text.ErrorTitle, ErrorCode: code, ErrorMessage: translatedError(lang, code), BackLabel: text.Back,
	})
}

func preferredLanguage(request *http.Request) string {
	if request.URL.Query().Get("lang") == "zh-CN" || strings.Contains(strings.ToLower(request.Header.Get("Accept-Language")), "zh") {
		return "zh-CN"
	}
	return "en"
}

func translatedError(lang, code string) string {
	if value := errorTranslations[lang][code]; value != "" {
		return value
	}
	return errorTranslations[lang]["internal_error"]
}

func validAuthQuery(values url.Values) bool {
	for key := range values {
		if key != "transaction" && key != "lang" {
			return false
		}
	}
	return len(values["transaction"]) <= 1 && len(values["lang"]) <= 1
}

func parseAuthForm(writer http.ResponseWriter, request *http.Request, allowed ...string) (url.Values, error) {
	if !strings.HasPrefix(strings.ToLower(request.Header.Get("Content-Type")), "application/x-www-form-urlencoded") {
		return nil, errors.New("unsupported form content type")
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxAuthBodyBytes)
	if err := request.ParseForm(); err != nil {
		return nil, errors.New("invalid form")
	}
	allowedSet := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = true
	}
	for key, values := range request.PostForm {
		if !allowedSet[key] || len(values) != 1 {
			return nil, errors.New("invalid form field")
		}
	}
	for _, key := range allowed {
		if len(request.PostForm[key]) != 1 {
			return nil, errors.New("missing form field")
		}
	}
	return request.PostForm, nil
}

func browserError(err error) (int, string) {
	switch {
	case errors.Is(err, identity.ErrInvalidCredentials):
		return http.StatusUnauthorized, "invalid_credentials"
	case errors.Is(err, identity.ErrDuplicate):
		return http.StatusConflict, "registration_conflict"
	case errors.Is(err, identity.ErrInvalidInput):
		return http.StatusUnprocessableEntity, "invalid_input"
	case errors.Is(err, session.ErrInvalidCSRF):
		return http.StatusForbidden, "csrf_failed"
	case errors.Is(err, authn.ErrRegistrationDisabled):
		return http.StatusForbidden, "registration_disabled"
	case errors.Is(err, authn.ErrInvalidFlow):
		return http.StatusBadRequest, "invalid_authentication_flow"
	case errors.Is(err, identity.ErrHashBusy):
		return http.StatusTooManyRequests, "temporarily_unavailable"
	default:
		return http.StatusInternalServerError, "internal_error"
	}
}
