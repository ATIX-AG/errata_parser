#!/bin/sh

set -eu

BASEDIR="$(git rev-parse --show-toplevel)"
# enable pre-commit hook
ln -fs "../../scripts/pre-commit" "${BASEDIR}/.git/hooks/pre-commit"

