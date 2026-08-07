package httpserver

import (
	"errors"
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/authflow"
	"github.com/oneissuer/oneissuer/internal/authorization"
	"github.com/oneissuer/oneissuer/internal/oidc"
	"github.com/oneissuer/oneissuer/internal/session"
)

func (a *applicationHandler) handleAuthorize(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, request, http.MethodGet)
		return
	}
	verified, err := oidc.ParseAuthorizationRequest(request.Context(), request.URL.RawQuery, a.clients)
	if err != nil {
		a.writeAuthorizationError(writer, request, err)
		return
	}
	input := authflow.VerifiedInput{
		ClientID: verified.Client.ID, RedirectURI: verified.RedirectURI, Scopes: verified.Scopes,
		PKCEChallenge: verified.PKCEChallenge, State: verified.State, Nonce: verified.Nonce,
		PromptCreate: verified.Prompts.Has("create"), ResponseType: verified.ResponseType, ResponseMode: verified.ResponseMode,
		Prompts: verified.Prompts.Values(), MaxAgeSeconds: verified.MaxAge,
	}
	token, transaction, err := a.transactions.CreateVerified(request.Context(), input, RequestID(request.Context()), a.now().UTC())
	if err != nil {
		a.writeAuthorizationError(writer, request, &oidc.AuthorizationError{
			Code: oidc.ErrorServerError, HTTPStatus: http.StatusFound, SafeToRedirect: true,
			RedirectURI: verified.RedirectURI, State: verified.State,
		})
		return
	}
	a.advanceAuthorization(writer, request, token, transaction)
}

func (a *applicationHandler) handleAuthorizeContinuation(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, request, http.MethodGet)
		return
	}
	query := request.URL.Query()
	if len(query) != 1 || len(query["transaction"]) != 1 || query.Get("transaction") == "" {
		a.renderErrorPage(writer, request, http.StatusBadRequest, "invalid_authentication_flow")
		return
	}
	token := query.Get("transaction")
	transaction, err := a.transactions.Resolve(request.Context(), token, a.now().UTC())
	if err != nil || transaction.Kind != authflow.KindAuthorization {
		a.renderErrorPage(writer, request, http.StatusBadRequest, "invalid_authentication_flow")
		return
	}
	a.advanceAuthorization(writer, request, token, transaction)
}

func (a *applicationHandler) advanceAuthorization(writer http.ResponseWriter, request *http.Request, token string, transaction authflow.Transaction) {
	now := a.now().UTC()
	principal, err := a.sessions.Authenticate(request.Context(), a.cookies.SessionToken(request), now)
	if err != nil && !errors.Is(err, session.ErrUnauthenticated) {
		a.terminateAuthorization(writer, request, transaction, oidc.ErrorServerError, "server_error", nil)
		return
	}
	if errors.Is(err, session.ErrUnauthenticated) {
		if transactionHasPrompt(transaction, "none") {
			a.terminateAuthorization(writer, request, transaction, oidc.ErrorLoginRequired, "login_required", nil)
			return
		}
		if transactionHasPrompt(transaction, "create") {
			if !a.authn.CanRegister(request.Context(), transaction) {
				a.terminateAuthorization(writer, request, transaction, oidc.ErrorInteractionRequired, "interaction_required", nil)
				return
			}
			a.redirectToBrowserFlow(writer, "/register", token)
			return
		}
		a.redirectToBrowserFlow(writer, "/login", token)
		return
	}

	if transactionHasPrompt(transaction, "create") && !principal.AuthenticatedAt.After(transaction.CreatedAt) {
		a.terminateAuthorization(writer, request, transaction, oidc.ErrorInteractionRequired, "interaction_required", &principal.User.ID)
		return
	}
	if authorizationNeedsReauthentication(transaction, principal.AuthenticatedAt, now) {
		if transactionHasPrompt(transaction, "none") {
			a.terminateAuthorization(writer, request, transaction, oidc.ErrorLoginRequired, "login_required", &principal.User.ID)
			return
		}
		a.redirectToBrowserFlow(writer, "/login", token)
		return
	}

	_, evaluation, err := a.evaluateAuthorization(request.Context(), principal.User.ID, transaction)
	if err != nil {
		a.terminateAuthorization(writer, request, transaction, oidc.ErrorServerError, "client_disabled", &principal.User.ID)
		return
	}
	if evaluation.Covers && !transactionHasPrompt(transaction, "consent") {
		a.issueAuthorizationCode(writer, request, token, transaction, principal, false)
		return
	}
	if transactionHasPrompt(transaction, "none") {
		a.terminateAuthorization(writer, request, transaction, oidc.ErrorConsentRequired, "consent_required", &principal.User.ID)
		return
	}
	a.redirectToBrowserFlow(writer, "/consent", token)
}

func (a *applicationHandler) issueAuthorizationCode(writer http.ResponseWriter, request *http.Request, transactionToken string, transaction authflow.Transaction, principal session.Principal, interactive bool) {
	issued, err := a.authorization.Issue(
		request.Context(), transaction, principal.User.ID, principal.SessionID, principal.SessionBindingID,
		principal.AuthenticatedAt,
		interactive, RequestID(request.Context()), a.now().UTC(),
	)
	if err != nil {
		switch {
		case errors.Is(err, authorization.ErrConsumed), errors.Is(err, authorization.ErrExpired), errors.Is(err, authorization.ErrNotFound), errors.Is(err, authorization.ErrInvalid):
			a.renderErrorPage(writer, request, http.StatusBadRequest, "invalid_authentication_flow")
		case errors.Is(err, authorization.ErrConsentRequired) && !transactionHasPrompt(transaction, "none"):
			a.redirectToBrowserFlow(writer, "/consent", transactionToken)
		default:
			a.terminateAuthorization(writer, request, transaction, oidc.ErrorServerError, "server_error", &principal.User.ID)
		}
		return
	}
	location, err := oidc.BuildAuthorizationSuccessRedirect(transaction.RedirectURI, issued.Code, transaction.State)
	if err != nil {
		a.renderErrorPage(writer, request, http.StatusInternalServerError, "server_error")
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Location", location)
	writer.WriteHeader(http.StatusFound)
}

func (a *applicationHandler) redirectToBrowserFlow(writer http.ResponseWriter, path, transactionToken string) {
	target := &url.URL{Path: path, RawQuery: url.Values{"transaction": {transactionToken}}.Encode()}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Location", target.String())
	writer.WriteHeader(http.StatusSeeOther)
}

func (a *applicationHandler) terminateAuthorization(
	writer http.ResponseWriter,
	request *http.Request,
	transaction authflow.Transaction,
	code oidc.ErrorCode,
	reason string,
	actor *uuid.UUID,
) {
	if _, err := a.transactions.Reject(request.Context(), transaction, reason, actor, RequestID(request.Context()), a.now().UTC()); err != nil {
		code = oidc.ErrorServerError
	}
	a.writeAuthorizationError(writer, request, &oidc.AuthorizationError{
		Code: code, HTTPStatus: http.StatusFound, SafeToRedirect: true,
		RedirectURI: transaction.RedirectURI, State: transaction.State,
	})
}

func (a *applicationHandler) writeAuthorizationError(writer http.ResponseWriter, request *http.Request, err error) {
	var protocolError *oidc.AuthorizationError
	if !errors.As(err, &protocolError) {
		a.renderErrorPage(writer, request, http.StatusInternalServerError, "server_error")
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	if !protocolError.SafeToRedirect {
		status := protocolError.HTTPStatus
		if status < 400 || status > 599 {
			status = http.StatusBadRequest
		}
		a.renderErrorPage(writer, request, status, string(protocolError.Code))
		return
	}
	location, buildErr := oidc.BuildAuthorizationErrorRedirect(protocolError)
	if buildErr != nil {
		a.renderErrorPage(writer, request, http.StatusInternalServerError, "server_error")
		return
	}
	writer.Header().Set("Location", location)
	writer.WriteHeader(http.StatusFound)
}

func transactionHasPrompt(transaction authflow.Transaction, value string) bool {
	index := sort.SearchStrings(transaction.Prompts, value)
	return index < len(transaction.Prompts) && transaction.Prompts[index] == value
}

func authorizationNeedsReauthentication(transaction authflow.Transaction, authenticatedAt, now time.Time) bool {
	if transactionHasPrompt(transaction, "login") && authenticatedAt.Before(transaction.CreatedAt) {
		return true
	}
	if transaction.MaxAgeSeconds == nil {
		return false
	}
	if *transaction.MaxAgeSeconds == 0 {
		return authenticatedAt.Before(transaction.CreatedAt)
	}
	return now.After(authenticatedAt.UTC().Add(time.Duration(*transaction.MaxAgeSeconds) * time.Second))
}
