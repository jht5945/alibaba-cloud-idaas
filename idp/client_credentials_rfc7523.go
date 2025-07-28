package idp

import (
	"github.com/aliyunidaas/alibaba-cloud-idaas/config"
	"github.com/aliyunidaas/alibaba-cloud-idaas/oidc"
	"github.com/pkg/errors"
)

func FetchAccessTokenClientCredentialsRfc7523(credentialConfig *config.OidcTokenProviderClientCredentialsConfig) (string, error) {
	tokenEndpoint := credentialConfig.TokenEndpoint
	jwtSigner, err := config.NewExJwtSignerFromConfig(credentialConfig.ClientAssertionSinger)
	if err != nil {
		return "", errors.Wrap(err, "new jwt signer failed")
	}
	fetchTokenRfc7523Options := &oidc.FetchTokenRfc7523Options{
		FetchTokenCommonOptions: buildFetchTokenCommonOptions(credentialConfig),
		JwtSigner:               jwtSigner,
	}
	tokenResponse, errorResponse, err := oidc.FetchTokenRfc7523(tokenEndpoint, fetchTokenRfc7523Options)
	return parseFetchAccessToken(tokenResponse, errorResponse, err)
}
