// Copyright 2023 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

// Package auth0 provides a client package to talk to auth0.
package auth0

import (
	"context"

	"github.com/redpanda-data/redpanda/src/go/rpk/pkg/httpapi"
	"github.com/redpanda-data/redpanda/src/go/rpk/pkg/oauth"
)

// ProdEndpoint is the auth0 endpoint to get device tokens from.
var ProdEndpoint = Endpoint{
	URL:      "https://auth.prd.cloud.redpanda.com",
	Audience: "cloudv2-production.redpanda.cloud",
}

// RPKClientID is the auth0 client ID, it is public and is safe to have it here.
const RPKClientID = "AUj7Cn0C2SmpjY8pSi1Nyx7XF4zGkwcw" // TODO dev

// Config groups what url, audience, and clientID to use for getting tokens.
type Config struct {
	Auth0URL      string
	Auth0Audience string
	CloudURL      string
	CloudAudience string
}

// Client talks to auth0.
type Client struct {
	cfg    Config
	httpCl *httpapi.Client
}

func NewClient(cfg Config, rpkClientID string) *Client {
	opts := []httpapi.Opt{
		httpapi.Err4xx(func(code int) error { return &oauth.TokenResponseError{Code: code} }),
	}
	httpCl := httpapi.NewClient(opts...)

	if cfg.CloudURL == "" {
		cfg.CloudURL = "https://cloud-api.prd.cloud.redpanda.com" // Once we migrate to use Auth0 this must change to use AuthURL.
		cfg.CloudAudience = prodAuth0Endpoint.CloudAudience

	}

	cl := &Client{
		cfg:    cfg,
		httpCl: httpCl,
	}

	// Token
	auth0Endpoint := Endpoint{
		URL:      cfg.AuthURL,
		Audience: cfg.AuthAudience,
	}
	if auth0Endpoint.URL == "" {
		auth0Endpoint = prodAuth0Endpoint
	}

	if cfg.AuthClientID == "" {
		cfg.AuthClientID = prodClientID
	}
	return cl
}

func (cl *Client) Audience() string {
	return cl.endpoint.Audience
}

func (cl *Client) Token(context.Context, Config) (oauth.Token, error) {
	return cl.getToken(ctx, cl.cfg.Auth0URL, cl.cfg.Audience, cfg.ClientID, cfg.ClientSecret)
}

func (cl *Client) DeviceCode(context.Context, Config) (oauth.DeviceCode, error) {
	return cl.initDeviceAuthorization(ctx, cl.cfg.CloudURL, cfg.AuthClientID)
}

func (cl *Client) DeviceToken(ctx context.Context, clientID, deviceCode string) (oauth.Token, error) {
	return cl.getDeviceToken(ctx, cl.cfg.CloudURL, clientID, deviceCode)
}

/////////
// API //
/////////

func (cl *Client) getToken(ctx context.Context, host, audience, clientID, clientSecret string) (oauth.Token, error) {
	path := host + "/oauth/token"
	form := httpapi.Values(
		"grant_type", "client_credentials",
		"client_id", clientID,
		"client_secret", clientSecret,
		"audience", audience,
	)

	var token Token
	return token, cl.httpCl.PostForm(ctx, path, nil, form, &token)
}

func (cl *Client) initDeviceAuthorization(ctx context.Context, host, clientID string) (oauth.DeviceCode, error) {
	path := host + "/oauth/device/code"
	body := struct {
		ClientID string `json:"client_id"`
	}{clientID}

	var code oauth.DeviceCode
	return code, cl.httpCl.Post(ctx, path, nil, "application/json", body, &code)
}

func (cl *Client) getDeviceToken(ctx context.Context, host, authClientID, deviceCode string) (oauth.Token, error) {
	path := host + "/oauth/token"
	body := struct {
		ClientID   string `json:"client_id"`
		DeviceCode string `json:"device_code"`
		GrantType  string `json:"grant_type"`
	}{authClientID, deviceCode, "urn:ietf:params:oauth:grant-type:device_code"}

	var token oauth.Token
	return token, cl.httpCl.Post(ctx, path, nil, "application/json", body, &token)
}
