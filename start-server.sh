#!/bin/bash

set -euo pipefail

docker rm -f pebble || true
docker run -d --name pebble --net host letsencrypt/pebble
