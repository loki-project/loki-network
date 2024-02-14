
CLANG_FORMAT_DESIRED_VERSION=17

CLANG_FORMAT=$(command -v clang-format-$CLANG_FORMAT_DESIRED_VERSION 2>/dev/null)
if [ $? -ne 0 ]; then
    CLANG_FORMAT=$(command -v clang-format-mp-$CLANG_FORMAT_DESIRED_VERSION 2>/dev/null)
fi
if [ $? -ne 0 ]; then
    CLANG_FORMAT=$(command -v clang-format 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "Please install clang-format version $CLANG_FORMAT_DESIRED_VERSION and re-run this script."
        exit 1
    fi
    version=$(clang-format --version)
    if [[ ! $version == *"clang-format version $CLANG_FORMAT_DESIRED_VERSION"* ]]; then
        echo "Please install clang-format version $CLANG_FORMAT_DESIRED_VERSION and re-run this script."
        exit 1
    fi
fi
