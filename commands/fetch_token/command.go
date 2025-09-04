package fetch_token

import (
	"fmt"

	"github.com/aliyunidaas/alibaba-cloud-idaas/cloud"
	"github.com/aliyunidaas/alibaba-cloud-idaas/cloud/alibaba_cloud"
	"github.com/aliyunidaas/alibaba-cloud-idaas/cloud/aws"
	"github.com/aliyunidaas/alibaba-cloud-idaas/cloud/oidc"
	"github.com/aliyunidaas/alibaba-cloud-idaas/utils"
	"github.com/urfave/cli/v2"
)

var (
	stringFlagProfile = &cli.StringFlag{
		Name:    "profile",
		Aliases: []string{"p"},
		Usage:   "IDaaS Profile",
	}
	stringFlagFormat = &cli.StringFlag{
		Name:    "format",
		Aliases: []string{"f"},
		Usage:   "Cloud STS format, values aliyuncli(default), ossutilv2",
	}
	stringFlagOidcField = &cli.StringFlag{
		Name:  "oidc-field",
		Usage: "Fetch OIDC filed (id_token or access_token)",
	}
	boolFlagForceNew = &cli.BoolFlag{
		Name:    "force-new",
		Aliases: []string{"N"},
		Usage:   "Force fetch cloud STS token, ignore cache (including OpenId configuration etc.)",
	}
)

func BuildCommand() *cli.Command {
	flags := []cli.Flag{
		stringFlagProfile,
		stringFlagFormat,
		stringFlagOidcField,
		boolFlagForceNew,
	}
	return &cli.Command{
		Name:  "fetch-token",
		Usage: "Fetch cloud STS token",
		Flags: flags,
		Action: func(context *cli.Context) error {
			profile := context.String("profile")
			format := context.String("format")
			oidcField := context.String("oidc-field")
			forceNew := context.Bool("force-new")

			return fetchToken(profile, format, oidcField, forceNew)
		},
	}
}

func fetchToken(profile, format, oidcField string, forceNew bool) error {
	options := &cloud.FetchCloudStsOptions{
		ForceNew: forceNew,
	}
	oidcTokenType := oidc.GetOidcTokenType(oidcField)
	options.FetchOidcTokenType = oidcTokenType

	sts, _, err := cloud.FetchCloudStsFromDefaultConfig(profile, options)
	if err != nil {
		return err
	}

	var stdOutput string
	var stdOutputErr error
	printNewLine := true

	if alibabaCloudSts, ok := sts.(*alibaba_cloud.StsToken); ok {
		stdOutput, stdOutputErr = alibabaCloudSts.MarshalWithFormat(format)
	} else if awsStsToken, ok := sts.(*aws.AwsStsToken); ok {
		stdOutput, stdOutputErr = awsStsToken.Marshal()
	} else if oidcToken, ok := sts.(*oidc.OidcToken); ok {
		if oidcTokenType == oidc.FetchIdToken {
			printNewLine = false
			stdOutput = oidcToken.IdToken
		} else if oidcTokenType == oidc.FetchAccessToken {
			printNewLine = false
			stdOutput = oidcToken.AccessToken
		} else {
			stdOutput, stdOutputErr = oidcToken.Marshal()
		}
	} else {
		return fmt.Errorf("unknown cloud STS token type")
	}

	if stdOutputErr != nil {
		return stdOutputErr
	}
	if printNewLine {
		utils.Stdout.Println(stdOutput)
	} else {
		utils.Stdout.Print(stdOutput)
	}
	return nil
}
