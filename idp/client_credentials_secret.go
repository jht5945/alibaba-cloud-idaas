package idp

import (
	"github.com/aliyunidaas/alibaba-cloud-idaas/config"
	"github.com/aliyunidaas/alibaba-cloud-idaas/oidc"
)

func FetchAccessTokenClientCredentialsClientIdSecret(credentialConfig *config.OidcTokenProviderClientCredentialsConfig) (*oidc.TokenResponse, error) {
	tokenEndpoint := credentialConfig.TokenEndpoint
	fetchTokenOptions := &oidc.FetchTokenOptions{
		ClientId:     credentialConfig.ClientId,
		ClientSecret: credentialConfig.ClientSecret,
		GrantType:    oidc.GrantTypeClientCredentials,
		Scope:        credentialConfig.Scope,
	}

	tokenResponse, errorResponse, err := oidc.FetchToken(tokenEndpoint, fetchTokenOptions)
	return parseFetchAccessToken(tokenResponse, errorResponse, err)
}
