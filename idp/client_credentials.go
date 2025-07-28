package idp

import (
	"github.com/aliyunidaas/alibaba-cloud-idaas/config"
	"github.com/pkg/errors"
	"strings"
)

func FetchAccessTokenClientCredentials(credentialConfig *config.OidcTokenProviderClientCredentialsConfig) (string, error) {
	if credentialConfig == nil {
		return "", errors.New("oidcTokenProviderClientCredentialsConfig is nil")
	}
	if credentialConfig.TokenEndpoint == "" {
		return "", errors.New("oidcTokenProviderClientCredentialsConfig.TokenEndpoint is empty")
	}
	if credentialConfig.ClientId == "" {
		return "", errors.New("oidcTokenProviderClientCredentialsConfig.ClientId is empty")
	}

	hasClientSecret := credentialConfig.ClientSecret != ""
	hasClientAssertionSigner := credentialConfig.ClientAssertionSinger != nil
	hasClientAssertionPkcs7 := credentialConfig.ClientAssertionPkcs7Config != nil
	hasClientAssertionPrivateCa := credentialConfig.ClientAssertionPrivateCaConfig != nil
	hasClientAssertionOidcToken := credentialConfig.ClientAssertionOidcTokenConfig != nil

	var clientAuthMethods []string
	if hasClientSecret {
		clientAuthMethods = append(clientAuthMethods, "secret")
	}
	if hasClientAssertionSigner {
		clientAuthMethods = append(clientAuthMethods, "signer")
	}
	if hasClientAssertionPkcs7 {
		clientAuthMethods = append(clientAuthMethods, "pkcs7")
	}
	if hasClientAssertionPrivateCa {
		clientAuthMethods = append(clientAuthMethods, "private_ca")
	}
	if hasClientAssertionOidcToken {
		clientAuthMethods = append(clientAuthMethods, "oidc_token")
	}

	if len(clientAuthMethods) > 1 {
		return "", errors.Errorf("multiple client auth methods found: %s", strings.Join(clientAuthMethods, ", "))
	}

	if hasClientSecret {
		return FetchAccessTokenClientCredentialsClientIdSecret(credentialConfig)
	} else if hasClientAssertionSigner {
		return FetchAccessTokenClientCredentialsRfc7523(credentialConfig)
	} else if hasClientAssertionPkcs7 {
		return FetchAccessTokenClientCredentialsPkcs7(credentialConfig)
	} else if hasClientAssertionPrivateCa {
		return FetchAccessTokenClientCredentialsPrivateCa(credentialConfig)
	} else if hasClientAssertionOidcToken {
		return FetchAccessTokenClientCredentialsOidcToken(credentialConfig)
	} else {
		return "", errors.New("client auth method must set one")
	}
}
