#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PARENT=$(realpath $DIR/..)

source "$PARENT/framework_bash/lib/oo-bootstrap.sh"
source "$DIR/files.sh"

import util/type
import util/log

namespace patch

Log::AddOutput patch DEBUG

if [ -e "$PARENT/src/UTOPIA_KERNEL" ]; then
    echo "$(UI.Color.Yellow)This kernel is already configured for Utopia $(UI.Color.Default)"
    exit 0
fi

array folders=$(get_directory_structure_at "$PARENT/utopia")

for folder in "${folders[@]}"
do
    if [ ! -e "$PARENT/src/$folder" ]; then
        Log "Creating $folder"
        mkdir "$PARENT/src/$folder"
    fi
done

Log "Copying files"

array files="$(get_files_at $PARENT/utopia)"

UTOPIA_PATH="$PARENT/utopia"
KERNEL_PATH="$PARENT/src"

for file in "${files[@]}"
do
    if [ ! -e "$KERNEL_PATH/$file" ]; then
        Log "Copying $file"
        cp "$UTOPIA_PATH/$file" "$KERNEL_PATH/$file"
    fi
done

touch "$PARENT/src/UTOPIA_KERNEL"