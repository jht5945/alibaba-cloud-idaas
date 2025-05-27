package fetch_token

import (
	"fmt"
	"github.com/aliyunidaas/alibaba-cloud-idaas/cloud"
	"github.com/aliyunidaas/alibaba-cloud-idaas/cloud/alibaba_cloud"
	"github.com/aliyunidaas/alibaba-cloud-idaas/cloud/aws"
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
		boolFlagForceNew,
	}
	return &cli.Command{
		Name:  "fetch-token",
		Usage: "Fetch cloud STS token",
		Flags: flags,
		Action: func(context *cli.Context) error {
			profile := context.String("profile")
			format := context.String("format")
			forceNew := context.Bool("force-new")

			return fetchToken(profile, format, forceNew)
		},
	}
}

func fetchToken(profile, format string, forceNew bool) error {
	options := &cloud.FetchCloudStsOptions{
		ForceNew: forceNew,
	}
	sts, _, err := cloud.FetchCloudStsFromDefaultConfig(profile, options)
	if err != nil {
		return err
	}

	var stsJson string
	var stsJsonErr error

	if alibabaCloudSts, ok := sts.(*alibaba_cloud.StsToken); ok {
		stsJson, stsJsonErr = alibabaCloudSts.MarshalWithFormat(format)
	} else if awsStsToken, ok := sts.(*aws.AwsStsToken); ok {
		stsJson, stsJsonErr = awsStsToken.Marshal()
	} else {
		return fmt.Errorf("unknown cloud STS token type")
	}

	if stsJsonErr != nil {
		return stsJsonErr
	}
	utils.Stdout.Println(stsJson)
	return nil
}
