#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

if [ -n "${BN_USER_PLUGIN_DIR:-}" ]; then
    plugin_dir=$BN_USER_PLUGIN_DIR
elif [ "$(uname -s)" = "Darwin" ]; then
    plugin_dir="$HOME/Library/Application Support/Binary Ninja/plugins"
else
    plugin_dir="$HOME/.binaryninja/plugins"
fi

target="$plugin_dir/msp430x_lens"
if [ -L "$target" ]; then
    linked_path=$(readlink "$target")
    if [ "$linked_path" = "$repo_dir" ]; then
        echo "Development plugin is already linked: $target"
        exit 0
    fi
    echo "Refusing to replace existing symlink: $target -> $linked_path" >&2
    exit 1
fi
if [ -e "$target" ]; then
    echo "Refusing to replace existing plugin: $target" >&2
    exit 1
fi

mkdir -p "$plugin_dir"
ln -s "$repo_dir" "$target"
echo "Linked $target -> $repo_dir"
echo "Restart Binary Ninja to load the development checkout."
