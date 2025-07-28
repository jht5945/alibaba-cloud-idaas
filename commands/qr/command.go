package qr

import (
	"github.com/aliyunidaas/alibaba-cloud-idaas/utils"
	"github.com/pkg/errors"
	"github.com/skip2/go-qrcode"
	"github.com/urfave/cli/v2"
)

var (
	stringFlagContent = &cli.StringFlag{
		Name:  "content",
		Usage: "QR content",
	}
	boolFlagSmall = &cli.BoolFlag{
		Name:  "small",
		Usage: "Show small QR code",
	}
)

func BuildCommand() *cli.Command {
	flags := []cli.Flag{
		stringFlagContent,
		boolFlagSmall,
	}
	return &cli.Command{
		Name:  "qr",
		Usage: "Show QR code",
		Flags: flags,
		Action: func(context *cli.Context) error {
			content := context.String("content")
			small := context.Bool("small")

			if content == "" {
				content = "https://www.aliyun.com/product/idaas"
			}

			qrCode, err := qrcode.New(content, qrcode.Low)
			if err != nil {
				return errors.Errorf("failed to display QR Code: %v\n", err)
			}
			if qrCode != nil {
				if small {
					utils.Stderr.Print("QR code [small]:\n" + qrCode.ToSmallString(false))
				} else {
					utils.Stderr.Print("QR code [normal]:\n" + qrCode.ToString(false))
				}
			}

			return nil
		},
	}
}
