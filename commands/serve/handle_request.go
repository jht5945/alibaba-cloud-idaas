package serve

import (
	"github.com/aliyunidaas/alibaba-cloud-idaas/cloud"
	"github.com/aliyunidaas/alibaba-cloud-idaas/cloud/alibaba_cloud"
	"github.com/aliyunidaas/alibaba-cloud-idaas/cloud/aws"
	"net/http"
)

func handleCloudToken(w http.ResponseWriter, r *http.Request) {
	if !allowRequest(w, r, true) {
		return
	}
	query := r.URL.Query()

	// TODO SSRF
	// TODO memory cache
	// TODO current access
	profile := query.Get("profile")
	forceNew := query.Get("force-new")

	options := &cloud.FetchCloudStsOptions{
		ForceNew: forceNew == "true",
	}
	sts, _, err := cloud.FetchCloudStsFromDefaultConfig(profile, options)
	if err != nil {
		// TODO logging
		printResponse(w, http.StatusInternalServerError, ErrorResponse{
			Error:   "internal_error",
			Message: "Fetch cloud sts token failed.",
		})
		return
	}

	alibabaCloudSts, ok := sts.(*alibaba_cloud.StsToken)
	if ok {
		printResponse(w, http.StatusOK, alibabaCloudSts.ConvertToCredentialsUri())
		return
	}

	_, ok = sts.(*aws.AwsStsToken)
	if ok {
		printResponse(w, http.StatusNotImplemented, ErrorResponse{
			Error:   "not_implemented",
			Message: "AWS sts token sts not implemented.",
		})
		return
	}

	printResponse(w, http.StatusInternalServerError, ErrorResponse{
		Error:   "bad_request",
		Message: "Unknown cloud sts token.",
	})
	return
}
