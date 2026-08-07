package httpserver

import (
	"errors"
	"net/http"

	"github.com/oneissuer/oneissuer/internal/oidc"
	"github.com/oneissuer/oneissuer/internal/token"
)

func (a *applicationHandler) handleRevocation(writer http.ResponseWriter, request *http.Request) {
	setTokenResponseHeaders(writer.Header())
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, request, http.MethodPost)
		return
	}
	form, err := parseTokenForm(writer, request)
	if err != nil {
		writeOAuthError(writer, &oidc.TokenError{Code: "invalid_request", HTTPStatus: http.StatusBadRequest})
		return
	}
	operationCtx, cancel := operationContext(request)
	defer cancel()
	verified, err := oidc.ParseRevocationRequest(operationCtx, form, request.Header, a.tokenClients)
	if err != nil {
		writeLifecycleProtocolError(writer, err)
		return
	}
	if a.oauthClientRateLimited(verified.Client.ID) {
		a.writeOAuthRateLimitResponse(writer, request)
		return
	}
	if err := a.tokens.Revoke(operationCtx, token.RevocationInput{
		Client: verified.Client, Token: verified.Token, Hint: verified.Hint,
		RequestID: RequestID(request.Context()), Now: a.now().UTC(),
	}); err != nil {
		writeOAuthError(writer, &oidc.TokenError{Code: "server_error", HTTPStatus: http.StatusInternalServerError})
		return
	}
	writer.WriteHeader(http.StatusOK)
}

func (a *applicationHandler) handleIntrospection(writer http.ResponseWriter, request *http.Request) {
	setTokenResponseHeaders(writer.Header())
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, request, http.MethodPost)
		return
	}
	form, err := parseTokenForm(writer, request)
	if err != nil {
		writeOAuthError(writer, &oidc.TokenError{Code: "invalid_request", HTTPStatus: http.StatusBadRequest})
		return
	}
	operationCtx, cancel := operationContext(request)
	defer cancel()
	verified, err := oidc.ParseIntrospectionRequest(operationCtx, form, request.Header, a.tokenClients)
	if err != nil {
		writeLifecycleProtocolError(writer, err)
		return
	}
	if a.oauthClientRateLimited(verified.Client.ID) {
		a.writeOAuthRateLimitResponse(writer, request)
		return
	}
	response, err := a.tokens.Introspect(operationCtx, token.IntrospectionInput{
		Client: verified.Client, Token: verified.Token, Hint: verified.Hint, Now: a.now().UTC(),
	})
	if err != nil {
		writeOAuthError(writer, &oidc.TokenError{Code: "server_error", HTTPStatus: http.StatusInternalServerError})
		return
	}
	writeProtocolJSON(writer, http.StatusOK, response)
}

func writeLifecycleProtocolError(writer http.ResponseWriter, err error) {
	var protocolError *oidc.TokenError
	if !errors.As(err, &protocolError) {
		protocolError = &oidc.TokenError{Code: "server_error", HTTPStatus: http.StatusInternalServerError}
	}
	writeOAuthError(writer, protocolError)
}
