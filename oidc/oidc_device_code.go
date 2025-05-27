package oidc

import (
	"encoding/json"
	"github.com/aliyunidaas/alibaba-cloud-idaas/constants"
	"github.com/aliyunidaas/alibaba-cloud-idaas/idaaslog"
	"github.com/aliyunidaas/alibaba-cloud-idaas/utils"
	"github.com/pkg/errors"
	"github.com/skip2/go-qrcode"
	"net/http"
)

type FetchDeviceCodeFlowOptions struct {
	ClientId     string
	ClientSecret string
	AutoOpenUrl  bool
	ShowQrCode   bool
	SmallQrCode  bool
	ForceNew     bool
}

type FetchDeviceCodeOptions struct {
	ClientId string
	Scope    string
}

func FetchTokenViaDeviceCodeFlow(issuer string, options *FetchDeviceCodeFlowOptions) (*TokenResponse, error) {
	fetchOpenIdConfigurationOptions := &FetchOpenIdConfigurationOptions{
		ForceNew: options.ForceNew,
	}
	openIdConfiguration, err := FetchOpenIdConfiguration(issuer, fetchOpenIdConfigurationOptions)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch open id configuration, issuer: %s", issuer)
	}
	if openIdConfiguration.DeviceAuthorizationEndpoint == "" {
		return nil, errors.Errorf("deviceAuthorizationEndpoint is empty, issuer: %s", issuer)
	}
	deviceAuthorization := openIdConfiguration.DeviceAuthorizationEndpoint
	fetchDeviceCodeOptions := &FetchDeviceCodeOptions{
		ClientId: options.ClientId,
	}
	deviceCodeResponse, deviceCodeErrorResponse, err := FetchDeviceCodeWithRetry(deviceAuthorization, fetchDeviceCodeOptions)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch device code from: %s", deviceAuthorization)
	}
	if deviceCodeErrorResponse != nil {
		return nil, errors.Errorf("failed to fetch device code with response: %v", deviceCodeErrorResponse)
	}

	if options.ShowQrCode {
		qrCode, err := qrcode.New(deviceCodeResponse.VerificationUriComplete, qrcode.Low)
		if err != nil {
			utils.Stderr.Fprintf("failed to display QR Code: %v\n", err)
		}
		if qrCode != nil {
			if options.SmallQrCode {
				utils.Stderr.Print("Please scan QR code:\n" + qrCode.ToSmallString(false))
			} else {
				utils.Stderr.Print("Please scan QR code:\n" + qrCode.ToString(false))
			}
		}
	}
	if options.AutoOpenUrl {
		err := utils.OpenUrl(deviceCodeResponse.VerificationUriComplete)
		if err != nil {
			utils.Stderr.Fprintf("failed to open URL: %v\n", err)
		}
	}
	utils.Stderr.Fprintf("Open URL: %s , input user code: %s\n",
		deviceCodeResponse.VerificationUri, deviceCodeResponse.UserCode)
	utils.Stderr.Fprintf("or, direct open URL: %s\n", deviceCodeResponse.VerificationUriComplete)

	fetchTokenOptions := &FetchTokenOptions{
		ClientId:     options.ClientId,
		ClientSecret: options.ClientSecret,
		GrantType:    GrantTypeDeviceCode,
		DeviceCode:   deviceCodeResponse.DeviceCode,
	}
	sleepInterval := deviceCodeResponse.Interval
	tokenErrorCounting := 0
	for i := 0; i < 100; i++ {
		idaaslog.Debug.PrintfLn("Sleep %d s, #%d", sleepInterval, i)
		utils.SleepSeconds(sleepInterval)

		tokenResponse, tokenErrorResponse, err := FetchToken(openIdConfiguration.TokenEndpoint, fetchTokenOptions)
		if err != nil {
			tokenErrorCounting++
			if tokenErrorCounting > 3 {
				return nil, errors.Errorf("failed to fetch token with response: %w", err)
			}
			// LOGGING ...
			continue
		}
		// reset error counting
		tokenErrorCounting = 0
		if tokenErrorResponse != nil {
			idaaslog.Debug.PrintfLn("Token error with response: %+v", tokenErrorResponse)
			if tokenErrorResponse.Error == ErrorCodeAuthorizationPending {
				// JUST OK
			} else if tokenErrorResponse.Error == ErrorCodeSlowDown {
				sleepInterval++
			} else if tokenErrorResponse.Error == ErrorAccessDenied {
				utils.Stderr.Fprintf("failed to fetch token with response: %s", tokenErrorResponse.Error)
				return nil, errors.New(constants.ErrStopFallback)
			} else {
				utils.Stderr.Fprintf("failed to fetch token with response: %s", tokenErrorResponse.Error)
				return nil, errors.Errorf("failed to fetch token with response: %s", tokenErrorResponse.Error)
			}
		}
		if tokenResponse != nil {
			return tokenResponse, nil
		}
	}
	return nil, errors.Errorf("failed to fetch token")
}

func FetchDeviceCodeWithRetry(deviceAuthorization string, options *FetchDeviceCodeOptions) (
	deviceCodeResponse *DeviceCodeResponse, errorResponse *ErrorResponse, err error) {

	// try 3 times
	for i := 0; i < 3; i++ {
		deviceCodeResponse, errorResponse, err = FetchDeviceCode(deviceAuthorization, options)
		if err == nil {
			return
		}
		idaaslog.Warn.PrintfLn("Failed to fetch device code #%d, error: %v", i, err)
	}
	return
}

func FetchDeviceCode(deviceAuthorization string, options *FetchDeviceCodeOptions) (
	*DeviceCodeResponse, *ErrorResponse, error) {

	parameter := map[string]string{}
	parameter["client_id"] = options.ClientId
	if options.Scope == "" {
		parameter["scope"] = "openid"
	} else {
		parameter["scope"] = options.Scope
	}
	statusCode, deviceCode, err := utils.PostHttp(deviceAuthorization, parameter)
	if err != nil {
		idaaslog.Error.PrintfLn("Failed to fetch device code, error: %v", err)
		return nil, nil, err
	}
	if statusCode != http.StatusOK {
		errorResponse, err := parseErrorResponse(deviceCode)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "failed to parse error response: %s", deviceCode)
		}
		return nil, errorResponse, nil
	}
	idaaslog.Debug.PrintfLn("deviceCode: %v", deviceCode)
	var deviceCodeResponse DeviceCodeResponse
	err = json.Unmarshal([]byte(deviceCode), &deviceCodeResponse)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to unmarshal deviceCode response: %s", deviceCode)
	}
	return &deviceCodeResponse, nil, nil
}
