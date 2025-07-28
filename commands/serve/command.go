package serve

import (
	"fmt"
	"github.com/aliyunidaas/alibaba-cloud-idaas/constants"
	"github.com/urfave/cli/v2"
	"net/http"
	"time"
)

var (
	startup = time.Now().UnixMilli()
)

var (
	intFlagPort = &cli.IntFlag{
		Name:    "port",
		Aliases: []string{"p"},
		Usage:   "Port (default 1127)",
	}
	stringFlagUnsafeListenHost = &cli.StringFlag{
		Name:  "unsafe-listen-host",
		Usage: "Default listen 127.0.0.1, use this flag can assign to 0.0.0.0",
	}
	boolFlagUnsafeDisableSsrf = &cli.BoolFlag{
		Name:  "unsafe-disable-ssrf",
		Usage: "Disable SSRF feature",
	}
)

func BuildCommand() *cli.Command {
	flags := []cli.Flag{
		intFlagPort,
		stringFlagUnsafeListenHost,
		boolFlagUnsafeDisableSsrf,
	}
	return &cli.Command{
		Name:  "serve",
		Usage: "Serve local server",
		Flags: flags,
		Action: func(context *cli.Context) error {
			unsafeListenHost := context.String("unsafe-listen-host")
			port := context.Int("port")
			if port == 0 {
				port = 1127
			}
			if port <= 0 || port > 65535 {
				return fmt.Errorf("invalid port %d", port)
			}
			listenHostAndPort := getListenHostAndPort(unsafeListenHost, port)
			return serve(listenHostAndPort, &ServeOptions{
				SsrfToken: "", // TODO ...
			})
		},
	}
}

func serve(listenHostAndPort string, serveOptions *ServeOptions) error {
	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/version", handleVersion)
	http.HandleFunc("/cloud_token", handleCloudToken)

	fmt.Printf("Listen at %s...", listenHostAndPort)
	return http.ListenAndServe(listenHostAndPort, nil)
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	if !allowRequest(w, r, false) {
		return
	}
	printResponse(w, http.StatusNotFound, ErrorResponse{
		Error:   "not_found",
		Message: "Resource not found.",
	})
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	if !allowRequest(w, r, false) {
		return
	}
	printResponse(w, http.StatusOK, VersionResponse{
		Name:    "alibaba-cloud-idaas",
		Version: constants.AlibabaCloudIdaasCliVersion,
		Startup: startup,
	})
}

func getListenHostAndPort(unsafeListenHost string, port int) string {
	var listenHostAndPort string
	if unsafeListenHost == "" {
		listenHostAndPort = fmt.Sprintf("127.0.0.1:%d", port)
	} else {
		// may be unsafe
		listenHostAndPort = fmt.Sprintf("%s:%d", unsafeListenHost, port)
	}
	return listenHostAndPort
}
