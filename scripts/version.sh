#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PARENT=$(realpath $DIR/..)

source "$PARENT/framework_bash/lib/oo-bootstrap.sh"

import util/type

check_version() {
    [string] source_directory

    PRECHANGE_IFS=$IFS
    IFS=$'\n'

    map internal_version_map
    string internal_version_string="$(cat $source_directory/Makefile | head -n 5 | tail -n 4)"
    array internal_version=($internal_version_string)

    IFS=$PRECHANGE_IFS

    for element in "${internal_version[@]}"
    do
        PRECHANGE_IFS=$IFS
        string component=$(echo $element | sed 's/ //g')
        IFS='='
        read -r key value <<< "$component"
        if [ "$value" != "" ]; then
            internal_version_map[$key]=$value
        fi
        IFS=$PRECHANGE_IFS
    done

    version="${internal_version_map[VERSION]}.${internal_version_map[PATCHLEVEL]}.${internal_version_map[SUBLEVEL]}"
    
    @return version
}