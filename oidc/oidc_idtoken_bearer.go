package oidc

type FetchTokenIdTokenBearerOptions struct {
	*FetchTokenCommonOptions
	IdToken string
}

func FetchTokenIdTokenBearer(tokenEndpoint string, options *FetchTokenIdTokenBearerOptions) (*TokenResponse, *ErrorResponse, error) {
	fetchTokenOptions := &FetchTokenOptions{
		ClientId:                           options.ClientId,
		GrantType:                          options.GrantType,
		Scope:                              options.Scope,
		ClientAssertionType:                ClientAssertionTypeIdTokenBearer,
		ClientAssertion:                    options.IdToken,
		ApplicationFederatedCredentialName: options.ApplicationFederatedCredentialName,
	}

	return FetchToken(tokenEndpoint, fetchTokenOptions)
}
