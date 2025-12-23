#!/bin/bash

PACK_NAME="$1"

if [ -z "$PACK_NAME" ]; then
  echo "Usage: $0 <PackName>"
  exit 1
fi

PACK_PATH="Packs/${PACK_NAME}"

cd ..
python3 demisto_sdk/__main__.py upload -i "${PACK_PATH}" --xsiam
