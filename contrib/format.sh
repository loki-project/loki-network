#!/usr/bin/env bash

# set -x
set -e

. $(dirname $0)/format-version.sh

cd "$(dirname $0)/../"

sources=($(find jni daemon llarp include pybind | grep -E '\.([hc](pp)?|m(m)?)$' | grep -v '#'))

incl_pat='^(#include +)"(llarp|libntrup|oxen|oxenc|oxenmq|quic|CLI|cpr|nlohmann|ghc|fmt|spdlog|uvw?)([/.][^"]*)"'

if [ "$1" = "verify" ] ; then
    if [ $($CLANG_FORMAT --output-replacements-xml "${sources[@]}" | grep '</replacement>' | wc -l) -ne 0 ] ; then
        exit 2
    fi

    if grep --color -E "$incl_pat" "${sources[@]}"; then
        exit 5
    fi
else
    $CLANG_FORMAT -i "${sources[@]}" &> /dev/null

    perl -pi -e "s{$incl_pat}"'{$1<$2$3>}' "${sources[@]}" &> /dev/null
fi

# Some includes just shouldn't exist anywhere, but need to be fixed manually:
if grep --color -E '^#include ([<"]external/|<bits/|<.*/impl)' "${sources[@]}"; then
    echo "Format failed: bad includes detected that can't be auto-corrected"
    exit 5
fi

swift_format=$(command -v swiftformat 2>/dev/null)
if [ $? -eq 0 ]; then
    if [ "$1" = "verify" ] ; then
        for f in $(find daemon | grep -E '\.swift$' | grep -v '#') ; do
            if [ $($swift_format --quiet --dryrun < "$f" | diff "$f" - | wc -l) -ne 0 ] ; then
                exit 3
            fi
        done
    else
        $swift_format --quiet $(find daemon | grep -E '\.swift$' | grep -v '#')
    fi

fi

jsonnet_format=$(command -v jsonnetfmt 2>/dev/null)
if [ $? -eq 0 ]; then
    if [ "$1" = "verify" ]; then
        if ! $jsonnet_format --test .drone.jsonnet; then
            exit 4
        fi
    else
        $jsonnet_format --in-place .drone.jsonnet
    fi
fi
