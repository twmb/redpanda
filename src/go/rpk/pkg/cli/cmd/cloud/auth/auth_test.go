package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/redpanda-data/redpanda/src/go/rpk/pkg/cli/cmd/cloud/cloudcfg"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

type (
	mockFlow         func(ctx context.Context, cfg *cloudcfg.Config) (*Token, error)
	mockAuthProvider struct {
		mockCredentialFlow mockFlow
		mockDeviceFlow     mockFlow
	}
)

func (m mockAuthProvider) ClientCredentialFlow(ctx context.Context, cfg *cloudcfg.Config) (*Token, error) {
	if m.mockCredentialFlow != nil {
		return m.mockCredentialFlow(ctx, cfg)
	}
	return nil, errors.New("credential flow not implemented")
}

func (m mockAuthProvider) DeviceFlow(ctx context.Context, cfg *cloudcfg.Config, _ func(string) error) (*Token, error) {
	if m.mockDeviceFlow != nil {
		return m.mockDeviceFlow(ctx, cfg)
	}
	return nil, errors.New("device flow not implemented")
}

func TestLoadFlow(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *cloudcfg.Config
		deviceFlow mockFlow
		credFlow   mockFlow
		exp        string
		expErr     bool
	}{
		{
			name: "client credetials",
			cfg: &cloudcfg.Config{
				ClientSecret: "secret",
				ClientID:     "id",
			},
			credFlow: func(_ context.Context, _ *cloudcfg.Config) (*Token, error) {
				return &Token{AccessToken: "success-credential"}, nil
			},
			exp:    "success-credential",
			expErr: false,
		},
		{
			name: "device flow",
			cfg: &cloudcfg.Config{
				ClientID: "id",
			},
			deviceFlow: func(_ context.Context, _ *cloudcfg.Config) (*Token, error) {
				return &Token{AccessToken: "success-device"}, nil
			},
			exp:    "success-device",
			expErr: false,
		},
		{
			name: "choose client credentials over device if credentials are provided",
			cfg: &cloudcfg.Config{
				ClientSecret: "secret",
				ClientID:     "id",
			},
			credFlow: func(_ context.Context, _ *cloudcfg.Config) (*Token, error) {
				return &Token{AccessToken: "success-credential"}, nil
			},
			deviceFlow: func(_ context.Context, _ *cloudcfg.Config) (*Token, error) {
				return &Token{AccessToken: "success-device"}, nil
			},
			exp:    "success-credential",
			expErr: false,
		},
		{
			name: "errs if a provider err",
			cfg: &cloudcfg.Config{
				ClientID: "id",
			},
			deviceFlow: func(_ context.Context, _ *cloudcfg.Config) (*Token, error) {
				return nil, errors.New("some error")
			},
			expErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			t.Setenv("HOME", "/tmp")
			m := mockAuthProvider{
				mockCredentialFlow: tt.credFlow,
				mockDeviceFlow:     tt.deviceFlow,
			}
			gotToken, err := LoadFlow(context.Background(), fs, tt.cfg, m)
			if tt.expErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Assert that we got the right token.
			require.Equal(t, tt.exp, gotToken)

			// Now check if it got written to disk.
			dir, err := os.UserConfigDir()
			require.NoError(t, err)
			fileLocation := filepath.Join(dir, "rpk", "__cloud.yaml")

			file, err := afero.ReadFile(fs, fileLocation)
			require.NoError(t, err)
			expFile := fmt.Sprintf("client_id: %s\nauth_token: %s\n", tt.cfg.ClientID, gotToken)
			require.Equal(t, string(file), expFile)
		})
	}
}
