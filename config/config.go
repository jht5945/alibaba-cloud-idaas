package config

import (
	"encoding/json"
	"github.com/aliyunidaas/alibaba-cloud-idaas/idaaslog"
)

const (
	Version1 = "1"
)

type CloudCredentialConfig struct {
	Version        string                     `json:"version"` // current version always ("1" - Version1)
	CurrentProfile string                     `json:"current_profile"`
	Profile        map[string]*CloudStsConfig `json:"profile"` // required
}

func (c *CloudCredentialConfig) FindProfile(profile string) (string, *CloudStsConfig) {
	if c == nil {
		return "", nil
	}
	idaaslog.Debug.PrintfLn("Init profile: %s", profile)
	if profile == "" {
		if c.CurrentProfile != "" {
			profile = c.CurrentProfile
			idaaslog.Info.PrintfLn("Current profile: %s", profile)
		} else {
			profile = "default"
			idaaslog.Info.PrintfLn("Default profile: %s", profile)
		}
	}
	p, ok := c.Profile[profile]
	if ok {
		idaaslog.Info.PrintfLn("Profile found: %s", profile)
		return profile, p
	} else {
		idaaslog.Info.PrintfLn("Profile not found: %s", profile)
		return profile, nil
	}
}

type CloudStsConfig struct {
	AlibabaCloud *AlibabaCloudStsConfig `json:"alibaba_cloud_sts"` // optional, AlibabaCloud or Aws one required
	Aws          *AwsCloudStsConfig     `json:"aws_sts"`           // optional, see AlibabaCloud
	Environments []string               `json:"environments"`      // optional, environments for execute
	Comment      string                 `json:"comment"`           // optional
}

type AlibabaCloudStsConfig struct {
	Region            string                   `json:"region"`
	StsEndpoint       string                   `json:"sts_endpoint"`        // required
	OidcProviderArn   string                   `json:"oidc_provider_arn"`   // required
	RoleArn           string                   `json:"role_arn"`            // required
	DurationSeconds   int64                    `json:"duration_seconds"`    // optional
	RoleSessionName   string                   `json:"role_session_name"`   // optional, generate role session name when absent
	OidcTokenProvider *OidcTokenProviderConfig `json:"oidc_token_provider"` // required at this moment
}

type AwsCloudStsConfig struct {
	Region            string                   `json:"region"`              // required
	RoleArn           string                   `json:"role_arn"`            // required
	DurationSeconds   int32                    `json:"duration_seconds"`    // optional
	RoleSessionName   string                   `json:"role_session_name"`   // optional, generate role session name when absent
	OidcTokenProvider *OidcTokenProviderConfig `json:"oidc_token_provider"` // required at this moment
}

type OidcTokenProviderConfig struct {
	OidcTokenProviderClientCredentials *OidcTokenProviderClientCredentialsConfig `json:"client_credentials"` // optional *
	OidcTokenProviderDeviceCode        *OidcTokenProviderDeviceCodeConfig        `json:"device_code"`        // optional *
	// * client_credentials and device_code requires one
}

func (c *OidcTokenProviderConfig) GetId() string {
	if c.OidcTokenProviderClientCredentials != nil {
		return c.OidcTokenProviderClientCredentials.ClientId
	}
	if c.OidcTokenProviderDeviceCode != nil {
		return c.OidcTokenProviderDeviceCode.ClientId
	}
	return "unknown_oidc"
}

func (c *OidcTokenProviderConfig) Marshal() string {
	if c == nil {
		return "\"null\""
	}
	configJson, err := json.Marshal(c)
	if err != nil {
		return "\"error:" + err.Error() + "\""
	}
	return string(configJson)
}

type OidcTokenProviderClientCredentialsConfig struct {
	TokenEndpoint         string          `json:"token_endpoint"`          // required
	ClientId              string          `json:"client_id"`               // required
	Scope                 string          `json:"scope"`                   // optional
	ClientSecret          string          `json:"client_secret"`           // optional *
	ClientAssertionSinger *ExSingerConfig `json:"client_assertion_singer"` // optional *
	// * client_secret and client_assertion_singer requires one
}

type OidcTokenProviderDeviceCodeConfig struct {
	Issuer       string `json:"issuer"`        // required
	ClientId     string `json:"client_id"`     // required
	Scope        string `json:"scope"`         // optional, default openid
	ClientSecret string `json:"client_secret"` // optional, when public client
	AutoOpenUrl  bool   `json:"auto_open_url"` // optional, auto open in browser, use in local device
	ShowQrCode   bool   `json:"show_qr_code"`  // optional, show QR code, use in server
	SmallQrCode  bool   `json:"small_qr_code"` // optional, show small QR code, may cause compatible issue
}

type ExSingerConfig struct {
	KeyID           string                         `json:"key_id"`           // required
	Algorithm       string                         `json:"algorithm"`        // required, RS256, RS384, RS512, ES256, ES384, ES512
	Pkcs11          *ExSignerPkcs11Config          `json:"pkcs11"`           // optional *
	YubikeyPiv      *ExSignerYubikeyPivConfig      `json:"yubikey_piv"`      // optional *
	ExternalCommand *ExSignerExternalCommandConfig `json:"external_command"` // optional *
	// * pkcs11, yubikey_piv and external_command requires one
}

type ExSignerPkcs11Config struct {
	LibraryPath string `json:"library_path"` // required
	TokenLabel  string `json:"token_label"`  // required
	KeyLabel    string `json:"key_label"`    // required
	Pin         string `json:"pin"`          // optional, or set env PKS11_PIN
}

type ExSignerYubikeyPivConfig struct {
	Slot      string `json:"slot"`       // required, auth,sign or rN
	Pin       string `json:"pin"`        // optional, or set env YUBIKEY_PIN
	PinPolicy string `json:"pin_policy"` // required, none, once or always
}
type ExSignerExternalCommandConfig struct {
	Command   string `json:"command"`   // required
	Parameter string `json:"parameter"` // required
}
