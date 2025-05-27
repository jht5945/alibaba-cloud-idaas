package idp

import (
	"github.com/aliyunidaas/alibaba-cloud-idaas/config"
	"github.com/aliyunidaas/alibaba-cloud-idaas/oidc"
	"github.com/pkg/errors"
)

func FetchAccessTokenClientCredentials(oidcTokenProviderClientCredentialsConfig *config.OidcTokenProviderClientCredentialsConfig) (string, error) {
	if oidcTokenProviderClientCredentialsConfig == nil {
		return "", errors.New("oidcTokenProviderClientCredentialsConfig is nil")
	}
	if oidcTokenProviderClientCredentialsConfig.TokenEndpoint == "" {
		return "", errors.New("oidcTokenProviderClientCredentialsConfig.TokenEndpoint is empty")
	}
	if oidcTokenProviderClientCredentialsConfig.ClientId == "" {
		return "", errors.New("oidcTokenProviderClientCredentialsConfig.ClientId is empty")
	}

	hasClientSecret := oidcTokenProviderClientCredentialsConfig.ClientSecret != ""
	hasClientAssertionSigner := oidcTokenProviderClientCredentialsConfig.ClientAssertionSinger != nil

	if hasClientSecret && hasClientAssertionSigner {
		return "", errors.New("ClientSecret and ClientAssertionSinger can't both be set")
	}

	if hasClientSecret {
		return FetchAccessTokenClientCredentialsClientIdSecret(oidcTokenProviderClientCredentialsConfig)
	} else if hasClientAssertionSigner {
		return FetchAccessTokenClientCredentialsRfc7523(oidcTokenProviderClientCredentialsConfig)
	} else {
		return "", errors.New("ClientSecret or ClientAssertionSinger must set at least one")
	}
}

func FetchAccessTokenClientCredentialsRfc7523(oidcTokenProviderClientCredentialsConfig *config.OidcTokenProviderClientCredentialsConfig) (string, error) {
	tokenEndpoint := oidcTokenProviderClientCredentialsConfig.TokenEndpoint
	jwtSigner, err := config.NewExJwtSignerFromConfig(oidcTokenProviderClientCredentialsConfig.ClientAssertionSinger)
	if err != nil {
		return "", errors.Wrap(err, "new jwt signer failed")
	}
	fetchTokenRfc7523Options := &oidc.FetchTokenRfc7523Options{
		TokenEndpoint: oidcTokenProviderClientCredentialsConfig.TokenEndpoint,
		ClientId:      oidcTokenProviderClientCredentialsConfig.ClientId,
		GrantType:     oidc.GrantTypeClientCredentials,
		Scope:         oidcTokenProviderClientCredentialsConfig.Scope,
		JwtSigner:     jwtSigner,
	}

	tokenResponse, errorResponse, err := oidc.FetchTokenRfc7523(tokenEndpoint, fetchTokenRfc7523Options)
	return parseFetchAccessToken(tokenResponse, errorResponse, err)
}

func FetchAccessTokenClientCredentialsClientIdSecret(oidcTokenProviderClientCredentialsConfig *config.OidcTokenProviderClientCredentialsConfig) (string, error) {
	tokenEndpoint := oidcTokenProviderClientCredentialsConfig.TokenEndpoint
	fetchTokenOptions := &oidc.FetchTokenOptions{
		ClientId:     oidcTokenProviderClientCredentialsConfig.ClientId,
		ClientSecret: oidcTokenProviderClientCredentialsConfig.ClientSecret,
		GrantType:    oidc.GrantTypeClientCredentials,
		Scope:        oidcTokenProviderClientCredentialsConfig.Scope,
	}

	tokenResponse, errorResponse, err := oidc.FetchToken(tokenEndpoint, fetchTokenOptions)
	return parseFetchAccessToken(tokenResponse, errorResponse, err)
}

func parseFetchAccessToken(tokenResponse *oidc.TokenResponse, errorResponse *oidc.ErrorResponse, err error) (string, error) {
	if err != nil {
		return "", err
	}
	if errorResponse != nil {
		return "", errors.Errorf("fetch token failed, error: %s, description: %s",
			errorResponse.Error, errorResponse.ErrorDescription)
	}
	return tokenResponse.AccessToken, nil
}
