#!/bin/bash

set -v -e -o pipefail

if [ "$COVERAGE" = true ]; then
    dub test --coverage :base
    dub test --coverage :phobos
    dub test --coverage :openssl
    wget https://codecov.io/bash -O codecov.sh
    bash codecov.sh
else
    dub test :base
    dub test :phobos
    dub test :openssl
fi
