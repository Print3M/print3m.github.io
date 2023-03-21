#!/usr/bin/env bash

set -ueo pipefail

ENV_FILE='./.env'
NOTES_DIR='./_notes'

if ! [[ -f "$ENV_FILE" ]]; then
    echo "Error: '.env' file not found." >&2
    exit 1
fi

# shellcheck source=/dev/null
source "$ENV_FILE"

if [[ -z "$GH_NOTES_REPO" ]]; then
    echo "Error: 'GH_NOTES_REPO' env variable is not set." >&2
    exit 1
fi

rm -rf "$NOTES_DIR"
mkdir "$NOTES_DIR"
git clone "$GH_NOTES_REPO" "$NOTES_DIR"
rm -rf "$NOTES_DIR/.git" "$NOTES_DIR/.vscode"