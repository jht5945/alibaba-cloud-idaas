package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func (c *CloudStsConfig) Digest() string {
	if c == nil {
		return ""
	}
	// Comment do not effect digest(cache)
	return digest(c.AlibabaCloud.Digest(), c.Aws.Digest())
}

func (c *AlibabaCloudStsConfig) Digest() string {
	if c == nil {
		return ""
	}
	return digest(c.Region, c.StsEndpoint, c.OidcProviderArn, c.RoleArn,
		fmt.Sprintf("%d", c.DurationSeconds), c.RoleSessionName, c.OidcTokenProvider.Digest())
}

func (c *AwsCloudStsConfig) Digest() string {
	if c == nil {
		return ""
	}
	return digest(c.Region, c.RoleArn, fmt.Sprintf("%d", c.DurationSeconds),
		c.RoleSessionName, c.OidcTokenProvider.Digest())
}

func (c *OidcTokenProviderConfig) Digest() string {
	if c == nil {
		return ""
	}
	return digest(c.OidcTokenProviderClientCredentials.Digest(), c.OidcTokenProviderDeviceCode.Digest())
}

func (c *OidcTokenProviderClientCredentialsConfig) Digest() string {
	if c == nil {
		return ""
	}
	// ClientSecret do note effect digest(cache)
	return digest(c.TokenEndpoint, c.ClientId, c.Scope, c.ClientAssertionSinger.Digest())
}

func (c *OidcTokenProviderDeviceCodeConfig) Digest() string {
	if c == nil {
		return ""
	}
	// ClientSecret, AutoOpenUrl, ShowQrCode, SmallQrCode do not effect digest(cache)
	return digest(c.Issuer, c.ClientId, c.Scope)
}

func (c *ExSingerConfig) Digest() string {
	if c == nil {
		return ""
	}
	return digest(c.KeyID, c.Algorithm,
		c.Pkcs11.Digest(), c.YubikeyPiv.Digest(), c.ExternalCommand.Digest())
}

func (c *ExSignerPkcs11Config) Digest() string {
	if c == nil {
		return ""
	}
	// Pin do not effect digest(cache)
	return digest(c.LibraryPath, c.TokenLabel, c.KeyLabel)
}

func (c *ExSignerYubikeyPivConfig) Digest() string {
	if c == nil {
		return ""
	}
	// Pin, PinPolicy do note effect digest(cache)
	return digest(c.Slot)
}

func (c *ExSignerExternalCommandConfig) Digest() string {
	if c == nil {
		return ""
	}
	return digest(c.Command, c.Parameter)
}

func digest(args ...string) string {
	h := sha256.New()
	for _, a := range args {
		h.Write([]byte(a))
	}
	return hex.EncodeToString(h.Sum(nil))
}
