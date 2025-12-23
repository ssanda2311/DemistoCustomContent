#!/bin/bash

PACK_NAME="$1"

if [ -z "$PACK_NAME" ]; then
  echo "Usage: $0 <PackName>"
  exit 1
fi

cd ..

python3 demisto_sdk/__main__.py init --pack -n "${PACK_NAME}" --xsiam -o Packs   