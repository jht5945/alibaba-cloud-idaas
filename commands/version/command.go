package version

import (
	"fmt"
	"github.com/aliyunidaas/alibaba-cloud-idaas/constants"
	"github.com/urfave/cli/v2"
)

func BuildCommand() *cli.Command {
	var flags []cli.Flag
	return &cli.Command{
		Name:  "version",
		Usage: "Version",
		Flags: flags,
		Action: func(context *cli.Context) error {
			return version()
		},
	}
}

func version() error {
	fmt.Printf("Version: %s\n", constants.AlibabaCloudIdaasCliVersion)
	return nil
}
