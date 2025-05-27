package utils

import (
	"fmt"
	"github.com/aliyunidaas/alibaba-cloud-idaas/constants"
	"github.com/pkg/errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

var UserAgent = getUserAgent()

func PostHttp(postUrl string, parameters map[string]string) (int, string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	postBody := ""
	for key, value := range parameters {
		if len(postBody) > 0 {
			postBody += "&"
		}
		postBody += url.QueryEscape(key) + "=" + url.QueryEscape(value)
	}
	req, err := http.NewRequest("POST", postUrl, strings.NewReader(postBody))
	if err != nil {
		return 0, "", errors.Wrapf(err, "new request: %s", postUrl)
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", errors.Wrapf(err, "do post request: %s", postUrl)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", errors.Wrapf(err, "read response body: %s", postUrl)
	}
	return resp.StatusCode, string(body), nil
}

func GetHttp(getUrl string) (int, string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	req, err := http.NewRequest("GET", getUrl, nil)
	if err != nil {
		return 0, "", errors.Wrapf(err, "new request: %s", getUrl)
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", errors.Wrapf(err, "do get request: %s", getUrl)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", errors.Wrapf(err, "read response body: %s", getUrl)
	}
	return resp.StatusCode, string(body), nil
}

func getUserAgent() string {
	userAgent := os.Getenv(constants.EnvUserAgent)
	if userAgent != "" {
		return userAgent + " AlibabaCloudIDaaS/2.0"
	}
	return fmt.Sprintf("%s/%s AlibabaCloudIDaaS/2.0",
		runtime.GOOS, runtime.GOARCH)
}
