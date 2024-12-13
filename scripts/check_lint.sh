#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

echo "Running $0"

DOCKER_CMD=${DOCKER_CMD:-docker}
GOLANGCI_LINT_IMAGE="golangci/golangci-lint:v1.62.2"
SHARED_OPTS="--rm --security-opt seccomp=unconfined -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace"

if [ ! $(command -v ${DOCKER_CMD}) ]; then
    exit 0
fi

echo "linting root directory.."
${DOCKER_CMD} run ${SHARED_OPTS} -w /opt/workspace ${GOLANGCI_LINT_IMAGE} golangci-lint run
echo "done linting root directory"

echo "Done Running $0"
