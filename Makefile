# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0


# Tool commands (overridable)
DOCKER_CMD ?= docker

GOBIN_PATH=$(abspath .)/build/bin
MOCKGEN=$(GOBIN_PATH)/mockgen
GOMOCKS=pkg/internal/gomocks
MOCK_VERSION 	?=v1.7.0-rc.1

OS := $(shell uname)
ifeq  ($(OS),$(filter $(OS),Darwin Linux))
	PATH:=$(PATH):$(GOBIN_PATH)
else
	PATH:=$(PATH);$(subst /,\\,$(GOBIN_PATH))
endif

.PHONY: all
all: clean checks unit-test

.PHONY: checks
checks: generate license lint

.PHONY: lint
lint: generate
	@scripts/check_lint.sh

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: unit-test
unit-test: generate
	@scripts/check_unit.sh

.PHONY: clean
clean:
	@rm -rf ./.build
	@rm -rf coverage*.out

.PHONY: generate
generate:
	@GOBIN=$(GOBIN_PATH) go install github.com/golang/mock/mockgen@$(MOCK_VERSION)
	@go generate ./...

.PHONY: tidy-modules
tidy-modules:
	@find . -type d \( -name build -prune \) -o -name go.mod -print | while read -r gomod_path; do \
		dir_path=$$(dirname "$$gomod_path"); \
		echo "Executing 'go mod tidy' in directory: $$dir_path"; \
		(cd "$$dir_path" && GOPROXY=$(GOPROXY) go mod tidy) || exit 1; \
	done