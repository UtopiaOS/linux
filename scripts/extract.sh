DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PARENT=$(realpath $DIR/..)

source "$PARENT/framework_bash/lib/oo-bootstrap.sh"

import util/namedParameters
import util/log
import util/type

namespace extract

Log::AddOutput extract DEBUG
Log::AddOutput error STDERR

extract_package() {
    [string] input_directory
    [string] output_directory
    [string] package

    pushd $input_directory
        string file_extension=$(echo $package | awk -F'[.]' '{print $NF}')
        if [ "$file_extension" == "xz" ]; then
            xz -cd "$input_directory/$package" | tar -xvf -
        elif [ "$file_extension" == "gz" ]; then
            gzip -cd "$input_directory/$package" | tar -xvf -
        else
            subject=error Log "File extension unkown, possibly corrupt file"
            exit 1
        fi
    popd

}