package httpserver

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/oneissuer/oneissuer/internal/oidc"
	"github.com/oneissuer/oneissuer/internal/token"
)

const (
	maxTokenBodyBytes        = 8 << 10
	maxUserInfoBodyBytes     = 8 << 10
	maxBearerTokenBytes      = 16 << 10
	maxAuthorizationHdrBytes = 24 << 10
)

type oauthErrorResponse struct {
	Error string `json:"error"`
}

func (a *applicationHandler) handleToken(writer http.ResponseWriter, request *http.Request) {
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
	verified, err := oidc.ParseTokenRequest(request.Context(), form, request.Header, a.tokenClients)
	if err != nil {
		var protocolError *oidc.TokenError
		if !errors.As(err, &protocolError) {
			protocolError = &oidc.TokenError{Code: "server_error", HTTPStatus: http.StatusInternalServerError}
		}
		writeOAuthError(writer, protocolError)
		return
	}
	response, err := a.tokens.Exchange(request.Context(), token.ExchangeInput{
		CodeHash: verified.CodeHash, Client: verified.Client, RedirectURI: verified.RedirectURI,
		CodeVerifier: verified.CodeVerifier, RequestID: RequestID(request.Context()), Now: a.now().UTC(),
	})
	if err != nil {
		protocolError := &oidc.TokenError{Code: "server_error", HTTPStatus: http.StatusInternalServerError}
		if errors.Is(err, token.ErrInvalidGrant) {
			protocolError = &oidc.TokenError{Code: "invalid_grant", HTTPStatus: http.StatusBadRequest}
		}
		writeOAuthError(writer, protocolError)
		return
	}
	writeProtocolJSON(writer, http.StatusOK, response)
}

func (a *applicationHandler) handleUserInfo(writer http.ResponseWriter, request *http.Request) {
	setTokenResponseHeaders(writer.Header())
	if request.Method != http.MethodGet && request.Method != http.MethodPost {
		methodNotAllowed(writer, request, http.MethodGet, http.MethodPost)
		return
	}
	compact, err := parseUserInfoBearer(writer, request)
	if err != nil {
		writeBearerError(writer, "invalid_token", http.StatusUnauthorized)
		return
	}
	result, err := a.tokens.UserInfoForAccessToken(request.Context(), compact, a.now().UTC())
	if err != nil {
		writeBearerError(writer, "invalid_token", http.StatusUnauthorized)
		return
	}
	writeProtocolJSON(writer, http.StatusOK, result)
}

func parseTokenForm(writer http.ResponseWriter, request *http.Request) (url.Values, error) {
	if request.URL.RawQuery != "" || request.URL.ForceQuery || len(request.Header.Values("Content-Type")) != 1 {
		return nil, errors.New("invalid token request")
	}
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "application/x-www-form-urlencoded") || len(parameters) != 0 {
		return nil, errors.New("invalid token content type")
	}
	if request.ContentLength > maxTokenBodyBytes {
		return nil, errors.New("token form is too large")
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxTokenBodyBytes)
	encoded, err := io.ReadAll(request.Body)
	if err != nil || len(encoded) == 0 {
		return nil, errors.New("invalid token form")
	}
	values, err := url.ParseQuery(string(encoded))
	if err != nil {
		return nil, errors.New("invalid token form encoding")
	}
	return values, nil
}

func parseUserInfoBearer(writer http.ResponseWriter, request *http.Request) (string, error) {
	if request.URL.RawQuery != "" || request.URL.ForceQuery {
		return "", errors.New("userinfo query parameters are not accepted")
	}
	if request.ContentLength > maxUserInfoBodyBytes {
		return "", errors.New("userinfo body is too large")
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxUserInfoBodyBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil || len(body) != 0 {
		return "", errors.New("userinfo body credentials are not accepted")
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 || len(values[0]) > maxAuthorizationHdrBytes {
		return "", errors.New("invalid Bearer authorization")
	}
	value := values[0]
	space := strings.IndexByte(value, ' ')
	if space != len("Bearer") || !strings.EqualFold(value[:space], "Bearer") || space+1 >= len(value) ||
		strings.ContainsAny(value[space+1:], " \t\r\n,") {
		return "", errors.New("invalid Bearer authorization")
	}
	compact := value[space+1:]
	if len(compact) > maxBearerTokenBytes || strings.Count(compact, ".") != 2 {
		return "", errors.New("invalid Bearer token")
	}
	return compact, nil
}

func setTokenResponseHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
}

func writeOAuthError(writer http.ResponseWriter, protocolError *oidc.TokenError) {
	status := http.StatusInternalServerError
	code := "server_error"
	if protocolError != nil {
		if protocolError.Code != "" {
			code = protocolError.Code
		}
		if protocolError.HTTPStatus >= 400 && protocolError.HTTPStatus <= 599 {
			status = protocolError.HTTPStatus
		}
		if protocolError.Code == "invalid_client" {
			status = http.StatusUnauthorized
		}
		if protocolError.BasicChallenge {
			writer.Header().Set("WWW-Authenticate", "Basic")
		}
	}
	writeProtocolJSON(writer, status, oauthErrorResponse{Error: code})
}

func writeBearerError(writer http.ResponseWriter, code string, status int) {
	writer.Header().Set("WWW-Authenticate", "Bearer")
	writeProtocolJSON(writer, status, oauthErrorResponse{Error: code})
}

func writeProtocolJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
