#!/usr/bin/env bash

VERSION=$1

LIST=(
    "alibaba-cloud-idaas-macosx-$VERSION-amd64.tgz"
    "alibaba-cloud-idaas-macosx-$VERSION-arm64.tgz"
    "alibaba-cloud-idaas-macosx-$VERSION-universal.tgz"
    "alibaba-cloud-idaas-linux-$VERSION-amd64.tgz"
    "alibaba-cloud-idaas-linux-$VERSION-arm64.tgz"
    "alibaba-cloud-idaas-windows-$VERSION-amd64.zip"
)

for filename in "${LIST[@]}"
do
    curl -fsSL -O \
        -H "Authorization: Bearer $GITHUB_TOKEN" \
        https://github.com/aliyunidaas/alibaba-cloud-idaas/releases/download/v"$VERSION"/"$filename"
    shasum -a 256 "$filename" >> SHASUMS256.txt
done

cat ./SHASUMS256.txt
