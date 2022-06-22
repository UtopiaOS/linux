#!/bin/bash


DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PARENT=$(realpath $DIR/..)
CONFIG="$PARENT/config.json"

source "$PARENT/framework_bash/lib/oo-bootstrap.sh"
source "$DIR/download.sh"
source "$DIR/extract.sh"
source "$DIR/version.sh"

import util/log
import util/type

namespace import

Log::AddOutput import DEBUG

Log "Extracting configuration"

string LINUX_VERSION=$(cat $CONFIG | jq -r ".version")
string LINUX_SHA256SUM=$(cat $CONFIG | jq -r ".shasum")

if [ -e "$PARENT/src" ]; then
    string version=$(check_version "$PARENT/src")
    if [ $version == "$LINUX_VERSION" ]; then
        echo "$(UI.Color.Yellow)Current version is the same as the one in the config, skipping import$(UI.Color.Default)"
        exit 0
    else
        Log "Creating src directory"
        mkdir "$PARENT/src"
    fi
fi


# Internal names in order to download
string LINUX_MAJOR=$(echo $LINUX_VERSION | awk '{split($0,a,"."); print a[1]}')
string LINUX_NAME="linux-$LINUX_VERSION"
string LINUX_PKG="$LINUX_NAME.tar.xz"
string LINUX_URL="https://cdn.kernel.org/pub/linux/kernel/v$LINUX_MAJOR.x/$LINUX_PKG"
Log "Building for Linux $LINUX_VERSION"

string temp_download_dir=$(mktemp -d /tmp/utopia-linux.XXXXXXXX)

download_package $temp_download_dir $LINUX_PKG $LINUX_SHA256SUM $LINUX_URL $LINUX_NAME
extract_package $temp_download_dir "$PARENT/src" $LINUX_PKG

echo "$(UI.Color.Green)Source imported. Run $DIR/patch.sh to apply patches"