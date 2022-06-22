
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PARENT=$(realpath $DIR/..)

source "$PARENT/framework_bash/lib/oo-bootstrap.sh"

import util/namedParameters
import util/type

get_directory_structure_at() {
    [string] source_directory

    string structure="$(find -L $source_directory -type d -printf '%P\n')"

    array structure_array=($structure)

    @return structure_array
}

get_files_at() {
    [string] source_directory

    string files="$(find -L $source_directory -type f -printf '%P\n')"
    array files_array=($files)

    @return files_array
}