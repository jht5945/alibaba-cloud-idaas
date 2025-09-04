package show_token

import (
	"github.com/aliyunidaas/alibaba-cloud-idaas/cloud"
	"github.com/aliyunidaas/alibaba-cloud-idaas/cloud/oidc"
	"github.com/aliyunidaas/alibaba-cloud-idaas/commands/common"
	"github.com/urfave/cli/v2"
)

var (
	stringFlagProfile = &cli.StringFlag{
		Name:    "profile",
		Aliases: []string{"p"},
		Usage:   "IDaaS Profile",
	}
	stringFlagOidcField = &cli.StringFlag{
		Name:  "oidc-field",
		Usage: "Fetch OIDC filed (id_token or access_token)",
	}
	boolFlagNoColor = &cli.BoolFlag{
		Name:  "no-color",
		Usage: "Output without color",
	}
	boolFlagForceNew = &cli.BoolFlag{
		Name:    "force-new",
		Aliases: []string{"N"},
		Usage:   "Force fetch cloud STS token, ignore cache (including OpenID configuration etc.)",
	}
)

func BuildCommand() *cli.Command {
	flags := []cli.Flag{
		stringFlagProfile,
		stringFlagOidcField,
		boolFlagNoColor,
		boolFlagForceNew,
	}
	return &cli.Command{
		Name:  "show-token",
		Usage: "Show cloud STS token",
		Flags: flags,
		Action: func(context *cli.Context) error {
			profile := context.String("profile")
			oidcField := context.String("oidc-field")
			color := !context.Bool("no-color")
			forceNew := context.Bool("force-new")
			return fetchAndShowToken(profile, oidcField, forceNew, color)
		},
	}
}

func fetchAndShowToken(profile, oidcField string, forceNew bool, color bool) error {
	options := &cloud.FetchCloudStsOptions{
		ForceNew: forceNew,
	}
	oidcTokenType := oidc.GetOidcTokenType(oidcField)
	options.FetchOidcTokenType = oidcTokenType

	sts, _, err := cloud.FetchCloudStsFromDefaultConfig(profile, options)
	if err != nil {
		return err
	}

	return common.ShowToken(sts, oidcTokenType, true, color)
}
