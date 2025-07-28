package serve

import (
	"encoding/json"
	"io"
	"net/http"
)

type ServeOptions struct {
	SsrfToken string
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

type VersionResponse struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Startup int64  `json:"startup"`
}

func printResponse(w http.ResponseWriter, code int, response any) {
	w.WriteHeader(code)
	w.Header().Set("Content-Type", "application/json")
	responseJson, err := json.Marshal(response)
	if err == nil {
		_, _ = w.Write(responseJson)
	}
}

func allowRequest(w http.ResponseWriter, r *http.Request, allowGet bool) bool {
	if allowGet && r.Method == http.MethodGet {
		// just allow
	} else if r.Method != http.MethodPost {
		// for security purpose, we only allow POST method, GET requests are easy to make
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = io.WriteString(w, "Not allowed.\n")
		printResponse(w, http.StatusMethodNotAllowed, ErrorResponse{
			Error:   "not_allowed",
			Message: "Method not allowed.",
		})
		return false
	}
	return true
}
