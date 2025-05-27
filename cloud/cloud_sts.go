package cloud

import (
	"fmt"
	"github.com/aliyunidaas/alibaba-cloud-idaas/cloud/alibaba_cloud"
	"github.com/aliyunidaas/alibaba-cloud-idaas/cloud/aws"
	"github.com/aliyunidaas/alibaba-cloud-idaas/config"
	"github.com/pkg/errors"
	"strings"
)

type FetchCloudStsOptions struct {
	ForceNew bool
}

func FetchCloudStsFromDefaultConfig(profile string, options *FetchCloudStsOptions) (any, *config.CloudStsConfig, error) {
	cloudCredentialConfig, err := config.LoadDefaultCloudCredentialConfig()
	if err != nil {
		return nil, nil, err
	}
	profile, cloudStsConfig := cloudCredentialConfig.FindProfile(profile)
	if cloudStsConfig == nil {
		return nil, cloudStsConfig, fmt.Errorf("profile: %s not found", profile)
	}
	sts, err := FetchCloudSts(profile, cloudStsConfig, options)
	if err != nil {
		return nil, cloudStsConfig, err
	}
	return sts, cloudStsConfig, nil
}

func FetchCloudSts(profile string, cloudStsConfig *config.CloudStsConfig, options *FetchCloudStsOptions) (any, error) {
	hasAlibabaCloud := cloudStsConfig.AlibabaCloud != nil
	hasAws := cloudStsConfig.Aws != nil

	var clouds []string
	if hasAlibabaCloud {
		clouds = append(clouds, "AlibabaCloud")
	}
	if hasAws {
		clouds = append(clouds, "Aws")
	}

	if len(clouds) > 1 {
		return nil, fmt.Errorf("multiple counds: %s found for profile: %s",
			strings.Join(clouds, ", "), profile)
	}

	if hasAlibabaCloud {
		stsOptions := &alibaba_cloud.FetchStsWithOidcConfigOptions{
			ForceNew: options.ForceNew,
		}
		return alibaba_cloud.FetchStsWithOidcConfig(profile, cloudStsConfig.AlibabaCloud, stsOptions)
	} else if hasAws {
		awsStsOptions := &aws.FetchAwsStsWithOidcConfigOptions{
			ForceNew: options.ForceNew,
		}
		return aws.FetchAwsStsWithOidcConfig(profile, cloudStsConfig.Aws, awsStsOptions)
	} else {
		return nil, errors.New("no clouds is set")
	}
}
