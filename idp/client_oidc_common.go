package idp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aliyunidaas/alibaba-cloud-idaas/config"
	"github.com/aliyunidaas/alibaba-cloud-idaas/constants"
	"github.com/aliyunidaas/alibaba-cloud-idaas/idaaslog"
	"github.com/aliyunidaas/alibaba-cloud-idaas/utils"
	"github.com/pkg/errors"
	"strings"
	"time"
)

type FetchOidcTokenOptions struct {
	ForceNew bool
}

func FetchOidcToken(profile string, oidcTokenProviderConfig *config.OidcTokenProviderConfig, options *FetchOidcTokenOptions) (string, error) {
	digest := oidcTokenProviderConfig.Digest()
	readCacheFileOptions := &utils.ReadCacheOptions{
		Context: map[string]interface{}{
			"profile": profile,
			"digest":  digest,
			"config":  oidcTokenProviderConfig.Marshal(),
		},
		FetchContent: func() (int, string, error) {
			return fetchJwt(oidcTokenProviderConfig, options)
		},
		IsContentExpiringOrExpired: func(s *utils.StringWithTime) bool {
			return isContentExpiringOrExpired(s)
		},
		IsContentExpired: func(s *utils.StringWithTime) bool {
			return isContentExpired(s)
		},
		ForceNew: options.ForceNew,
	}

	oidcTokenProviderId := oidcTokenProviderConfig.GetId()
	cacheKey := fmt.Sprintf("%s_%s", oidcTokenProviderId, digest[0:32])
	idaaslog.Debug.PrintfLn("Cache key: %s %s", constants.CategoryOidcToken, cacheKey)
	jwt, err := utils.ReadCacheFileWithEncryptionCallback(
		constants.CategoryOidcToken, cacheKey, readCacheFileOptions)
	return jwt, err
}

func fetchJwt(oidcTokenProviderConfig *config.OidcTokenProviderConfig, options *FetchOidcTokenOptions) (int, string, error) {
	hasOidcTokenProviderDeviceCode := oidcTokenProviderConfig.OidcTokenProviderDeviceCode != nil
	hasOidcTokenProviderClientCredentials := oidcTokenProviderConfig.OidcTokenProviderClientCredentials != nil

	if hasOidcTokenProviderDeviceCode && hasOidcTokenProviderClientCredentials {
		return 600, "", errors.New(
			"OidcTokenProviderDeviceCode and OidcTokenProviderClientCredentials cannot both be set")
	}
	var oidcToken string
	var fetchOidcTokenErr error
	if hasOidcTokenProviderDeviceCode {
		oidcToken, fetchOidcTokenErr = FetchIdTokenDeviceCode(oidcTokenProviderConfig.OidcTokenProviderDeviceCode, options)
	} else if hasOidcTokenProviderClientCredentials {
		oidcToken, fetchOidcTokenErr = FetchAccessTokenClientCredentials(oidcTokenProviderConfig.OidcTokenProviderClientCredentials)
	} else {
		return 600, "", errors.New(
			"OidcTokenProviderDeviceCode or OidcTokenProviderClientCredentials must set at least one")
	}
	if fetchOidcTokenErr != nil {
		return 600, "", fetchOidcTokenErr
	}
	return 200, oidcToken, nil
}

func isContentExpiringOrExpired(s *utils.StringWithTime) bool {
	jwtTokenClaim, err := ParseJwtTokenClaim(s.Content)
	if err != nil {
		return true
	}
	valid := jwtTokenClaim.IsValidAtLeastThreshold(2 * time.Minute)
	idaaslog.Debug.PrintfLn("Check JWT is expiring or expired: %s", !valid)
	return !valid
}

func isContentExpired(s *utils.StringWithTime) bool {
	jwtTokenClaim, err := ParseJwtTokenClaim(s.Content)
	if err != nil {
		return true
	}
	valid := jwtTokenClaim.IsValidAtLeastThreshold(1 * time.Minute)
	idaaslog.Debug.PrintfLn("Check JWT is expired: %s", !valid)
	return !valid
}

type SimpleJwtClaims struct {
	Issuer       string `json:"iss"`
	Audience     string `json:"aud"`
	Subject      string `json:"sub"`
	IssueAt      int64  `json:"iat"` // Unix Epoch(seconds)
	ExpirationAt int64  `json:"exp"` // Unix Epoch(seconds)
}

func (t *SimpleJwtClaims) IsValidAtLeastThreshold(thresholdDuration time.Duration) bool {
	idaaslog.Debug.PrintfLn("Check JWT is valid, expiration: %s, threshold: %d ms",
		t.ExpirationAt, thresholdDuration.Milliseconds())
	valid := (t.ExpirationAt - time.Now().Unix()) > int64(thresholdDuration.Seconds())
	idaaslog.Info.PrintfLn("Check JWT is valid: %s", valid)
	return valid
}

func ParseJwtTokenClaim(jwt string) (*SimpleJwtClaims, error) {
	jwtParts := strings.Split(jwt, ".")
	if len(jwtParts) != 3 {
		return nil, errors.Errorf("Invalid JWT token: %s", jwt)
	}
	claimsJson, err := base64.RawURLEncoding.DecodeString(jwtParts[1])
	if err != nil {
		return nil, errors.Errorf("Invalid JWT token: %s, error: %+v", jwt, err)
	}
	var simpleJwtClaims SimpleJwtClaims
	err = json.Unmarshal(claimsJson, &simpleJwtClaims)
	if err != nil {
		return nil, errors.Errorf("Invalid JWT token: %s, error: %+v", jwt, err)
	}
	return &simpleJwtClaims, nil
}
