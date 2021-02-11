#!/usr/bin/env bash

root_dir=$(dirname "${BASH_SOURCE[0]}")

cmake "$root_dir/src" -B "$root_dir/obj" -DCMAKE_INSTALL_PREFIX="$root_dir/bin"
exit_code="$?"
if [[ "$exit_code" != 0 ]]; then
    exit $exit_code
fi

cmake --build "$root_dir/obj" --target install
