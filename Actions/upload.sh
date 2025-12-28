#!/bin/bash

PACK_PATH="$1"

if [ -z "$PACK_PATH" ]; then
  echo "Usage: $0 <PackName>"
  exit 1
fi

python3 demisto_sdk/__main__.py upload -i "${PACK_PATH}" --xsiam
