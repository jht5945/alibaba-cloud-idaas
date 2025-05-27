_:
  @just --list

# Build local (PKCS#11 and YubiKey PIV are enabled)
build:
  LANG=en_US.UTF-8 go build -ldflags "-X main.commitHash=$(git rev-parse HEAD) -X main.gitStatus=$(git status -b --short | base64)"

# Cross build MacOS, Linux, Windows (cross build will be disabled PKCS#11 and YubiKey PIV)
cross-build:
    GOOS=linux GOARCH=arm64 go build -tags disable_pkcs11,disable_yubikey_piv -ldflags "-X main.commitHash=$(git rev-parse HEAD) -X main.gitStatus=$(git status -b --short | base64)" -o alibaba-cloud-idaas-linux-arm64
    GOOS=linux GOARCH=amd64 go build -tags disable_pkcs11,disable_yubikey_piv -ldflags "-X main.commitHash=$(git rev-parse HEAD) -X main.gitStatus=$(git status -b --short | base64)" -o alibaba-cloud-idaas-linux-amd64
    GOOS=windows GOARCH=arm64 go build -tags disable_pkcs11,disable_yubikey_piv -ldflags "-X main.commitHash=$(git rev-parse HEAD) -X main.gitStatus=$(git status -b --short | base64)" -o alibaba-cloud-idaas-windows-arm64
    GOOS=windows GOARCH=amd64 go build -tags disable_pkcs11,disable_yubikey_piv -ldflags "-X main.commitHash=$(git rev-parse HEAD) -X main.gitStatus=$(git status -b --short | base64)" -o alibaba-cloud-idaas-windows-amd64
    GOOS=darwin GOARCH=arm64 go build -tags disable_pkcs11,disable_yubikey_piv -ldflags "-X main.commitHash=$(git rev-parse HEAD) -X main.gitStatus=$(git status -b --short | base64)" -o alibaba-cloud-idaas-darwin-arm64
    GOOS=darwin GOARCH=amd64 go build -tags disable_pkcs11,disable_yubikey_piv -ldflags "-X main.commitHash=$(git rev-parse HEAD) -X main.gitStatus=$(git status -b --short | base64)" -o alibaba-cloud-idaas-darwin-amd64

