package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError string
		shouldError   bool
	}{
		{
			name: "valid API key",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123def456"},
			},
			expectedKey: "abc123def456",
			shouldError: false,
		},
		{
			name:          "missing authorization header",
			headers:       http.Header{},
			expectedError: "no authorization header included",
			shouldError:   true,
		},
		{
			name: "empty authorization header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedError: "no authorization header included",
			shouldError:   true,
		},
		{
			name: "malformed header - missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123def456"},
			},
			expectedError: "malformed authorization header",
			shouldError:   true,
		},
		{
			name: "malformed header - only ApiKey without space",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedError: "malformed authorization header",
			shouldError:   true,
		},
		{
			name: "malformed header - missing key after ApiKey",
			headers: http.Header{
				"Authorization": []string{"ApiKey "},
			},
			expectedKey: "",
			shouldError: false,
		},
		{
			name: "valid API key with extra spaces",
			headers: http.Header{
				"Authorization": []string{"ApiKey  abc123def456"},
			},
			expectedKey: "",
			shouldError: false,
		},
		{
			name: "case sensitive ApiKey",
			headers: http.Header{
				"Authorization": []string{"apikey abc123def456"},
			},
			expectedError: "malformed authorization header",
			shouldError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if tt.shouldError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if err.Error() != tt.expectedError {
					t.Errorf("expected error '%s', got '%s'", tt.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if key != tt.expectedKey {
					t.Errorf("expected key '%s', got '%s'", tt.expectedKey, key)
				}
			}
		})
	}
}

func TestGetAPIKey_SpecificErrorType(t *testing.T) {
	// Test that the specific error type is returned for missing header
	headers := http.Header{}
	_, err := GetAPIKey(headers)

	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}
