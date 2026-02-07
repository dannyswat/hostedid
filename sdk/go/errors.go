package hostedid

import (
	"encoding/json"
	"fmt"
)

// Sentinel errors returned by the SDK.
var (
	// ErrNoToken is returned when no access token is found in the request.
	ErrNoToken = fmt.Errorf("hostedid: no access token provided")

	// ErrTokenInvalid is returned when the access token is invalid or expired.
	ErrTokenInvalid = fmt.Errorf("hostedid: token is invalid or expired")

	// ErrTokenForbidden is returned when the token is valid but the user lacks permission.
	ErrTokenForbidden = fmt.Errorf("hostedid: access forbidden")
)

// APIError represents an error response from the HostedID API.
type APIError struct {
	StatusCode int    `json:"-"`
	Code       string `json:"code"`
	Message    string `json:"message"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("hostedid: API error %d [%s]: %s", e.StatusCode, e.Code, e.Message)
}

// apiErrorWrapper matches the HostedID API error envelope.
type apiErrorWrapper struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func parseAPIError(statusCode int, body []byte) error {
	var wrapper apiErrorWrapper
	if err := json.Unmarshal(body, &wrapper); err == nil && wrapper.Error.Code != "" {
		return &APIError{
			StatusCode: statusCode,
			Code:       wrapper.Error.Code,
			Message:    wrapper.Error.Message,
		}
	}

	return &APIError{
		StatusCode: statusCode,
		Code:       "unknown",
		Message:    string(body),
	}
}

// IsAPIError checks whether err is an APIError and returns it.
func IsAPIError(err error) (*APIError, bool) {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr, true
	}
	return nil, false
}
