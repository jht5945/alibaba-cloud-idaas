package common

import (
	"fmt"
	"github.com/aliyunidaas/alibaba-cloud-idaas/cloud/alibaba_cloud"
	"github.com/aliyunidaas/alibaba-cloud-idaas/cloud/aws"
	"github.com/aliyunidaas/alibaba-cloud-idaas/utils"
	"strings"
	"time"
)

func ShowToken(sts any, stdout, color bool) error {
	alibabaCloudSts, ok := sts.(*alibaba_cloud.StsToken)
	if ok {
		return showStsToken(alibabaCloudSts, stdout, color)
	}
	awsStsToken, ok := sts.(*aws.AwsStsToken)
	if ok {
		return showAwsStsToken(awsStsToken, stdout, color)
	}

	return fmt.Errorf("unknown cloud STS token type")
}

func showStsToken(alibabaCloudSts *alibaba_cloud.StsToken, stdout, color bool) error {
	printRow("Access Key ID", alibabaCloudSts.AccessKeyId, stdout, color)
	printRow("Access Key Secret", alibabaCloudSts.AccessKeySecret, stdout, color)
	printRow("Security Token", alibabaCloudSts.StsToken, stdout, color)
	expiration, err := time.Parse(time.RFC3339Nano, alibabaCloudSts.Expiration)
	if err == nil {
		printRowExpiration(&expiration, stdout, color)
	} else {
		printRow("Expiration", alibabaCloudSts.Expiration, stdout, color)
	}
	return nil
}

func showAwsStsToken(awsStsToken *aws.AwsStsToken, stdout, color bool) error {
	printRow("Access Key ID", awsStsToken.AccessKeyId, stdout, color)
	printRow("Secret Access Key", awsStsToken.SecretAccessKey, stdout, color)
	printRow("Session Token", awsStsToken.SessionToken, stdout, color)
	printRowExpiration(&awsStsToken.Expiration, stdout, color)
	return nil
}

func printRowExpiration(expiration *time.Time, stdout, color bool) {
	nowUnix := time.Now().Unix()
	expiredStatus := ""
	termColor := utils.TermGreen
	if nowUnix >= expiration.Unix() {
		termColor = utils.TermRed
		expiredStatus = "Expired"
	} else {
		leftSeconds := expiration.Unix() - nowUnix
		termColor = getExpirationColor(leftSeconds)
		expiredStatus = fmt.Sprintf("Expires in %d minute(s)", leftSeconds/60)
	}
	if expiredStatus != "" {
		expiredStatus = fmt.Sprintf("   [%s]", expiredStatus)
	}
	printRowWithColor("Expiration", fmt.Sprintf("%s%s", expiration.Local(), expiredStatus), termColor, stdout, color)
}

func getExpirationColor(leftSeconds int64) string {
	termColor := utils.TermGreen
	if leftSeconds < 20*60 {
		termColor = utils.TermRed
	} else if leftSeconds < 30*60 {
		termColor = utils.TermYellow
	}
	return termColor
}

func printRow(header, value string, stdout, color bool) {
	var sb strings.Builder
	sb.WriteString(utils.Blue(utils.Bold(
		fmt.Sprintf("%s%s: ", header, strings.Repeat(" ", 18-len(header))), color), color))
	sb.WriteString(utils.Green(value, color))
	printStdio(sb.String(), stdout)
}

func printRowWithColor(header, value, termColor string, stdout, color bool) {
	var sb strings.Builder
	sb.WriteString(utils.Blue(utils.Bold(
		fmt.Sprintf("%s%s: ", header, strings.Repeat(" ", 18-len(header))), color), color))
	sb.WriteString(utils.WithColor(value, termColor, color))
	printStdio(sb.String(), stdout)
}

func printStdio(str string, stdout bool) {
	if stdout {
		utils.Stdout.Println(str)
	} else {
		utils.Stderr.Println(str)
	}
}
