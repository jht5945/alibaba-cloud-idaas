package idp

import (
	"github.com/aliyunidaas/alibaba-cloud-idaas/config"
	"github.com/aliyunidaas/alibaba-cloud-idaas/oidc"
	"github.com/pkg/errors"
)

func FetchIdTokenDeviceCode(oidcTokenProviderDeviceCodeConfig *config.OidcTokenProviderDeviceCodeConfig,
	fetchOptions *FetchOidcTokenOptions) (*oidc.TokenResponse, error) {
	issuer := oidcTokenProviderDeviceCodeConfig.Issuer
	options := &oidc.FetchDeviceCodeFlowOptions{
		ClientId:     oidcTokenProviderDeviceCodeConfig.ClientId,
		ClientSecret: oidcTokenProviderDeviceCodeConfig.ClientSecret,
		ShowQrCode:   oidcTokenProviderDeviceCodeConfig.ShowQrCode,
		SmallQrCode:  oidcTokenProviderDeviceCodeConfig.SmallQrCode,
		AutoOpenUrl:  oidcTokenProviderDeviceCodeConfig.AutoOpenUrl,
		ForceNew:     fetchOptions.ForceNew,
	}
	tokenResponse, err := oidc.FetchTokenViaDeviceCodeFlow(issuer, options)
	if err != nil {
		return nil, errors.Wrapf(err, "failed fetch id token via device code, issuer: %s", issuer)
	}
	return tokenResponse, nil
}
