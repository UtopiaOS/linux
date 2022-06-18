#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PARENT=$(realpath $DIR/..)

source "$PARENT/framework_bash/lib/oo-bootstrap.sh"

import util/namedParameters
import util/log

namespace downloads

Log::AddOutput downloads DEBUG

download_package() {
    [string] output_directory
    [string] package
    [string] sha256_sum
    [string] url
    [string] name

    pushd $output_directory
        calculated_sha256=""
        if [ -e $package ]; then
            calculated_sha256="$(sha256sum $package | cut -f1 -d' ')"
        fi

        if  [ "$calculated_sha256" != $sha256_sum ]; then
            rm -rf $package
            curl -LO $url
        else
            Log "Package already downloaded, skipping download for $package"
        fi
    popd
}