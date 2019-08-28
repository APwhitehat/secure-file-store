#!/usr/bin/env bash

set -eux
echo "Installing lint search engine..."
go get -u -v github.com/golangci/golangci-lint/cmd/golangci-lint

echo "Looking for lint..."
golangci-lint run -E misspell -E goimports -D deadcode -D unused