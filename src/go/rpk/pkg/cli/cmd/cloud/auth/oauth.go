package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/redpanda-data/redpanda/src/go/rpk/pkg/auth0"
	"github.com/redpanda-data/redpanda/src/go/rpk/pkg/cli/cmd/cloud/cloudcfg"
)

// oauthProvider is the interface that defines our authorization providers and
// their authentication flows.
type oauthProvider interface {
	ClientCredentialFlow(ctx context.Context, cfg *cloudcfg.Config) (*Token, error)
	DeviceFlow(ctx context.Context, cfg *cloudcfg.Config, urlOpener func(string) error) (*Token, error)
}

// Token is a response for an OAuth 2 access token request. The struct
// follows the RFC6749 definition, for documentation on fields, see sections
// 4.2.2 and 4.2.2.1:
//
//	https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2
type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

//////////////////////////
// Auth0 Implementation //
//////////////////////////

// The auth0 endpoint information to get dev tokens from.
var prodAuth0Endpoint = auth0.Endpoint{
	URL:      "https://auth.prd.cloud.redpanda.com",
	Audience: "cloudv2-production.redpanda.cloud",
}

// The auth0 client ID, is public and is safe to have it here.
var prodClientID = "AUj7Cn0C2SmpjY8pSi1Nyx7XF4zGkwcw" // TODO: populate with the prod client ID here

// BadClientTokenError is returned when the client ID is invalid or some other
// error occurs. This can be used as a hint that the client ID needs to be
// cleared as well.
type BadClientTokenError struct {
	Err error
}

func (e *BadClientTokenError) Error() string {
	return fmt.Sprintf("invalid client token: %v", e.Err)
}

type Provider struct{}

func NewAuth0Provider() Provider {
	return Provider{}
}

// ClientCredentialFlow initiates a client credential authorization flow with
// Auth0 to obtain an access token.
func (Provider) ClientCredentialFlow(ctx context.Context, cfg *cloudcfg.Config) (*Token, error) {
	auth0Endpoint := auth0.Endpoint{
		URL:      cfg.AuthURL,
		Audience: cfg.AuthAudience,
	}

	if auth0Endpoint.URL == "" {
		auth0Endpoint = prodAuth0Endpoint
	}

	// We only validate the token if we have the client ID, if one of them is
	// not present we just start the login flow again.
	if cfg.AuthToken != "" && cfg.ClientID != "" {
		expired, err := validateToken(auth0Endpoint, cfg.AuthToken, cfg.ClientID) //nolint:contextcheck // jwx/jwt package uses ctx.Background in a function down the stream
		if err != nil {
			return nil, &BadClientTokenError{err}
		}
		if !expired {
			return &Token{AccessToken: cfg.AuthToken}, nil
		}
	}

	auth0Resp, err := auth0.NewClient(auth0Endpoint).GetToken(ctx, cfg.ClientID, cfg.ClientSecret)
	if err != nil {
		return nil, err
	}
	return (*Token)(&auth0Resp), nil
}

// DeviceFlow initiates a device authorization flow with Auth0 to obtain an
// access token.
func (Provider) DeviceFlow(ctx context.Context, cfg *cloudcfg.Config, urlOpener func(string) error) (*Token, error) {
	auth0Endpoint := auth0.Endpoint{
		URL:      cfg.CloudURL, // Once we migrate to use Auth0 this must change to use AuthURL.
		Audience: cfg.AuthAudience,
	}

	if auth0Endpoint.URL == "" {
		auth0Endpoint = auth0.Endpoint{
			URL:      "https://cloud-api.prd.cloud.redpanda.com", // Once we migrate to use Auth0 this must change to use AuthURL.
			Audience: prodAuth0Endpoint.Audience,
		}
	}

	if cfg.AuthClientID == "" {
		cfg.AuthClientID = prodClientID
	}

	// We only validate the token if we have the client ID, if one of them is
	// not present we just start the login flow again.
	if cfg.AuthToken != "" && cfg.ClientID != "" {
		expired, err := validateToken(auth0Endpoint, cfg.AuthToken, cfg.ClientID) //nolint:contextcheck // jwx/jwt package uses ctx.Background in a function down the stream
		if err != nil {
			return nil, &BadClientTokenError{err}
		}
		if !expired {
			return &Token{AccessToken: cfg.AuthToken}, nil
		}
	}

	auth0Client := auth0.NewClient(auth0Endpoint)
	resp, err := auth0Client.InitDeviceAuthorization(ctx, cfg.AuthClientID)
	if err != nil {
		return nil, fmt.Errorf("unable to start authorization flow: %v", err)
	}

	if !isURL(resp.VerificationURLComplete) {
		return nil, fmt.Errorf("authorization server returned an invalid URL: %s; please contact Redpanda support", resp.VerificationURLComplete)
	}
	err = urlOpener(resp.VerificationURLComplete)
	if err != nil {
		return nil, fmt.Errorf("unable to open the web browser: %v", err)
	}

	fmt.Printf("We are attempting to open your browser for authentication. In case the browser does not open automatically, kindly access %q in your preferred browser and proceed to login.\n", resp.VerificationURLComplete)

	tokenInterval := 5
	if resp.Interval > 0 {
		tokenInterval = resp.Interval
	}

	auth0Resp, err := auth0Client.WaitForDeviceToken(ctx, resp.DeviceCode, cfg.AuthClientID, tokenInterval)
	if err != nil {
		return nil, err
	}

	// If everything succeeded, save the clientID to the one used to generate
	// the token
	cfg.ClientID = cfg.AuthClientID

	return (*Token)(&auth0Resp), nil
}

// validateToken validates a token and returns whether a refresh is needed and
// notifies the user if it does.
func validateToken(auth0Endpoint auth0.Endpoint, token, clientID string) (expired bool, err error) {
	err = auth0.ValidateToken(token, auth0Endpoint.Audience, clientID)
	if err == nil {
		return false, nil
	}
	if ee := (*auth0.ExpiredError)(nil); errors.As(err, &ee) {
		return true, nil
	}
	return false, err
}

func isURL(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}
