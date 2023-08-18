# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0


# Tool commands (overridable)
DOCKER_CMD ?= docker

GO_VER ?= 1.20.5
PROJECT_ROOT = github.com/hyperledger/aries-framework-go
GOBIN_PATH=$(abspath .)/build/bin
MOCKGEN=$(GOBIN_PATH)/mockgen
GOMOCKS=pkg/internal/gomocks

.PHONY: all
all: clean checks unit-test

.PHONY: checks
checks: license lint

.PHONY: lint
lint:
	@scripts/check_lint.sh

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: unit-test
unit-test:
	@scripts/check_unit.sh

.PHONY: clean
clean:
	@rm -rf ./.build
	@rm -rf coverage*.out