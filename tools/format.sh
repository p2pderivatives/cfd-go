#!/bin/sh
cd `git rev-parse --show-toplevel`

go fmt . ./types/... ./errors ./utils ./config ./apis/... ./service/... ./tests
