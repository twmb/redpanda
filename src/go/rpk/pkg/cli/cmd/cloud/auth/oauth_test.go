package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/redpanda-data/redpanda/src/go/rpk/pkg/auth0"
	"github.com/redpanda-data/redpanda/src/go/rpk/pkg/cli/cmd/cloud/cloudcfg"
	"github.com/stretchr/testify/require"
)

func TestAuth0Provider_ClientCredentialFlow(t *testing.T) {
	tests := []struct {
		name   string
		testFn func(t *testing.T) http.HandlerFunc
		cfg    *cloudcfg.Config
		exp    *Token
		expErr bool
	}{
		{
			name: "retrieve token -- validate correct endpoint",
			testFn: func(t *testing.T) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					require.Equal(t, "/oauth/token", r.URL.Path)
					b, err := json.Marshal(Token{
						AccessToken: "token!",
						ExpiresIn:   100,
						TokenType:   "bearer",
					})
					require.NoError(t, err)

					w.WriteHeader(http.StatusOK)
					_, err = w.Write(b)
					require.NoError(t, err)
				}
			},
			cfg: &cloudcfg.Config{ClientID: "id", ClientSecret: "secret"},
			exp: &Token{
				AccessToken: "token!",
				ExpiresIn:   100,
				TokenType:   "bearer",
			},
		},
		{
			name: "Validate already present token and return the same",
			testFn: func(t *testing.T) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					// Do nothing, we don't issue the request.
					t.Error("unexpected request")
				}
			},
			cfg: &cloudcfg.Config{
				// Expires in 2100-04-05T17:22:27.871Z
				AuthToken:    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE2ODA3MTUzNDcsImV4cCI6NDExMDYyODk0NywiYXVkIjoidGVzdC1hdWRpZW5jZSIsInN1YiI6InJvZ2dlciIsImF6cCI6ImlkIn0.lYutL1t47HTo1O-zA9QKBjHwtAlgbz3VzV5lT4kXO_g",
				ClientID:     "id",
				AuthAudience: "test-audience",
			},
			exp: &Token{AccessToken: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE2ODA3MTUzNDcsImV4cCI6NDExMDYyODk0NywiYXVkIjoidGVzdC1hdWRpZW5jZSIsInN1YiI6InJvZ2dlciIsImF6cCI6ImlkIn0.lYutL1t47HTo1O-zA9QKBjHwtAlgbz3VzV5lT4kXO_g"},
		},
		{
			name: "Generate new token if stored token is expired",
			testFn: func(t *testing.T) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					b, err := json.Marshal(Token{AccessToken: "newToken"})
					require.NoError(t, err)

					w.WriteHeader(http.StatusOK)
					_, err = w.Write(b)
					require.NoError(t, err)
				}
			},
			cfg: &cloudcfg.Config{
				// Expired in 2022-11-08T17:22:27.871Z
				AuthToken:    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE2ODA3MTUzNDcsImV4cCI6MTY2NzkyODE0NywiYXVkIjoidGVzdC1hdWRpZW5jZSIsInN1YiI6InJvZ2dlciIsImF6cCI6ImlkIn0.V54Kg6Zp1rC1ioFb86i8k58PaLlmgyYBCWwulPC9--0",
				ClientID:     "id",
				ClientSecret: "secret",
				AuthAudience: "test-audience",
			},
			exp: &Token{AccessToken: "newToken"},
		},
		{
			name: "Generate new token if we dont have Client ID",
			testFn: func(t *testing.T) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					b, err := json.Marshal(Token{AccessToken: "newToken"})
					require.NoError(t, err)

					w.WriteHeader(http.StatusOK)
					_, err = w.Write(b)
					require.NoError(t, err)
				}
			},
			cfg: &cloudcfg.Config{
				AuthToken:    "oldToken", // We generate one new in the absence of clientID since we are not able to validate the token.
				AuthAudience: "test-audience",
				ClientSecret: "secret",
			},
			exp: &Token{AccessToken: "newToken"},
		},
		{
			name: "Err if stored token is not valid",
			testFn: func(t *testing.T) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					// Do nothing, we don't issue the request.
					t.Error("unexpected request")
				}
			},
			cfg: &cloudcfg.Config{
				// Expires in 2100-04-05T17:22:27.871Z
				AuthToken:    "not valid",
				ClientID:     "id",
				AuthAudience: "test-audience",
			},
			expErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.testFn(t))
			defer server.Close()

			tt.cfg.AuthURL = server.URL
			pr := NewAuth0Provider()
			got, err := pr.ClientCredentialFlow(context.Background(), tt.cfg)
			if tt.expErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.exp, got)
		})
	}
}

func TestAuth0Provider_DeviceFlow(t *testing.T) {
	genDeviceResponse := func(deviceCode, urlComplete string) ([]byte, error) {
		resp := auth0.GetAuthURLResponse{
			DeviceCode:              deviceCode,
			VerificationURLComplete: urlComplete,
			Interval:                1,
		}
		return json.Marshal(resp)
	}
	noopURLOpener := func(string) error { return nil }

	tests := []struct {
		name   string
		testFn func(t *testing.T) http.HandlerFunc
		cfg    *cloudcfg.Config
		exp    *Token
		expErr bool
	}{
		{
			name: "retrieve token",
			testFn: func(t *testing.T) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/oauth/device/code" {
						resp, err := genDeviceResponse("dev", "https://www.redpanda.com")
						require.NoError(t, err)
						w.WriteHeader(http.StatusOK)
						w.Write(resp)
					}
					if r.URL.Path == "/oauth/token" {
						bodyBytes, err := io.ReadAll(r.Body)
						require.NoError(t, err)
						var body map[string]string
						err = json.Unmarshal(bodyBytes, &body)
						require.NoError(t, err)
						require.Equal(t, "urn:ietf:params:oauth:grant-type:device_code", body["grant_type"])
						require.Equal(t, "dev", body["device_code"])

						b, err := json.Marshal(Token{
							AccessToken: "token!",
							ExpiresIn:   100,
							TokenType:   "bearer",
						})
						require.NoError(t, err)
						w.WriteHeader(http.StatusOK)
						w.Write(b)
					}
				}
			},
			cfg: &cloudcfg.Config{AuthClientID: "id"},
			exp: &Token{
				AccessToken: "token!",
				ExpiresIn:   100,
				TokenType:   "bearer",
			},
		},
		{
			name: "Generate new token if we dont have Client ID",
			testFn: func(t *testing.T) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/oauth/device/code" {
						resp, err := genDeviceResponse("dev", "https://www.redpanda.com")
						require.NoError(t, err)
						w.WriteHeader(http.StatusOK)
						w.Write(resp)
					}
					if r.URL.Path == "/oauth/token" {
						b, err := json.Marshal(Token{AccessToken: "newToken"})
						require.NoError(t, err)
						w.WriteHeader(http.StatusOK)
						w.Write(b)
					}
				}
			},
			cfg: &cloudcfg.Config{
				AuthToken:    "oldToken", // We generate one new in the absence of clientID since we are not able to validate the token.
				AuthAudience: "test-audience",
			},
			exp: &Token{AccessToken: "newToken"},
		},
		{
			name: "Generate new token if stored token is expired",
			testFn: func(t *testing.T) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/oauth/device/code" {
						resp, err := genDeviceResponse("dev", "https://www.redpanda.com")
						require.NoError(t, err)
						w.WriteHeader(http.StatusOK)
						w.Write(resp)
					}
					if r.URL.Path == "/oauth/token" {
						b, err := json.Marshal(Token{AccessToken: "newToken"})
						require.NoError(t, err)
						w.WriteHeader(http.StatusOK)
						w.Write(b)
					}
				}
			},
			cfg: &cloudcfg.Config{
				// Expired in 2022-11-08T17:22:27.871Z
				AuthToken:    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE2ODA3MTUzNDcsImV4cCI6MTY2NzkyODE0NywiYXVkIjoidGVzdC1hdWRpZW5jZSIsInN1YiI6InJvZ2dlciIsImF6cCI6ImlkIn0.V54Kg6Zp1rC1ioFb86i8k58PaLlmgyYBCWwulPC9--0",
				AuthClientID: "id",
				AuthAudience: "test-audience",
			},
			exp: &Token{AccessToken: "newToken"},
		},
		{
			name: "Validate already present token and return the same",
			testFn: func(t *testing.T) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					// Do nothing, we don't issue the request.
					t.Error("unexpected request")
				}
			},
			cfg: &cloudcfg.Config{
				// Expires in 2100-04-05T17:22:27.871Z
				AuthToken:    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE2ODA3MTUzNDcsImV4cCI6NDExMDYyODk0NywiYXVkIjoidGVzdC1hdWRpZW5jZSIsInN1YiI6InJvZ2dlciIsImF6cCI6ImlkIn0.lYutL1t47HTo1O-zA9QKBjHwtAlgbz3VzV5lT4kXO_g",
				ClientID:     "id",
				AuthAudience: "test-audience",
			},
			exp: &Token{AccessToken: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE2ODA3MTUzNDcsImV4cCI6NDExMDYyODk0NywiYXVkIjoidGVzdC1hdWRpZW5jZSIsInN1YiI6InJvZ2dlciIsImF6cCI6ImlkIn0.lYutL1t47HTo1O-zA9QKBjHwtAlgbz3VzV5lT4kXO_g"},
		},
		{
			name: "err if the verification url is not valid",
			testFn: func(t *testing.T) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/oauth/device/code" {
						resp, err := genDeviceResponse("dev", "invalid-url")
						require.NoError(t, err)
						w.WriteHeader(http.StatusOK)
						w.Write(resp)
					}
				}
			},
			cfg:    &cloudcfg.Config{ClientID: "id"},
			expErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.testFn(t))
			defer server.Close()

			tt.cfg.CloudURL = server.URL
			pr := NewAuth0Provider()
			got, err := pr.DeviceFlow(context.Background(), tt.cfg, noopURLOpener)
			if tt.expErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.exp, got)
		})
	}
}
