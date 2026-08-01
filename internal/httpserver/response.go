package httpserver

import (
	"encoding/json"
	"net/http"
)

type statusResponse struct {
	Status    string `json:"status"`
	RequestID string `json:"request_id,omitempty"`
}

type errorEnvelope struct {
	Error errorResponse `json:"error"`
}

type errorResponse struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeError(writer http.ResponseWriter, request *http.Request, status int, code, message string) {
	writeJSON(writer, status, errorEnvelope{Error: errorResponse{
		Code:      code,
		Message:   message,
		RequestID: RequestID(request.Context()),
	}})
}
