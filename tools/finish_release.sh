#!/usr/bin/env bash

set -e

VERSION=$1

if [[ "$VERSION" == *"-beta" ]]; then
  echo "beta. skip."
else
  RELEASE_ID=$(curl -fsSL \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer $GITHUB_TOKEN" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    https://api.github.com/repos/aliyunidaas/alibaba-cloud-idaas/releases/tags/v"$VERSION" | jq '.["id"]')

  if [[ "$VERSION" == *"-preview"* ]]; then
    DATA='{"draft":false,"prerelease":true,"make_latest":false}'
  else
    DATA='{"draft":false,"prerelease":false,"make_latest":true}'
  fi
  curl -fsSL \
    -X PATCH \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer $GITHUB_TOKEN" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    https://api.github.com/repos/aliyunidaas/alibaba-cloud-idaas/releases/"$RELEASE_ID" \
    -d "$DATA"
fi
