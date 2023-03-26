#!/bin/bash

# The name for the docker image (and running container)
IMAGE_NAME=sample-github-app

# Store key.pem file in root directory locally but don't check it in
PROJECT_ROOT="$(dirname "${0}")"
LOCAL_PATH="${PROJECT_ROOT}/key.pem"
if [[ ! -f "${LOCAL_PATH}" ]] ; then
  echo "Private key file does exist. Either set KEY_FILE_PATH or place the key in '${DEFAULT_PATH}'"
  exit 1
fi

# Exit if anything goes wrong
set -ex

# Build the Docker image
docker build -t "${IMAGE_NAME}" "${PROJECT_ROOT}"

# Run the program
docker run \
  -it \
  --rm \
  --publish 9684:9684 \
  --volume "${LOCAL_PATH}:/app/mykey.pem" \
  --name "${IMAGE_NAME}" \
  "${IMAGE_NAME}"