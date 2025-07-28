package idp

import (
	"github.com/aliyunidaas/alibaba-cloud-idaas/config"
	"github.com/aliyunidaas/alibaba-cloud-idaas/oidc"
	"github.com/pkg/errors"
)

func buildFetchTokenCommonOptions(credentialConfig *config.OidcTokenProviderClientCredentialsConfig) *oidc.FetchTokenCommonOptions {
	return &oidc.FetchTokenCommonOptions{
		TokenEndpoint:                      credentialConfig.TokenEndpoint,
		ClientId:                           credentialConfig.ClientId,
		GrantType:                          oidc.GrantTypeClientCredentials,
		Scope:                              credentialConfig.Scope,
		ApplicationFederatedCredentialName: credentialConfig.ApplicationFederatedCredentialName,
	}
}

func parseFetchAccessToken(tokenResponse *oidc.TokenResponse, errorResponse *oidc.ErrorResponse, err error) (string, error) {
	if err != nil {
		return "", err
	}
	if errorResponse != nil {
		return "", errors.Errorf("fetch token failed, error: %s, description: %s, requestId: %s",
			errorResponse.Error, errorResponse.ErrorDescription, errorResponse.RequestId)
	}
	return tokenResponse.AccessToken, nil
}
