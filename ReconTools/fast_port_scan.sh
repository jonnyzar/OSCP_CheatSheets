#!/bin/bash

TARGET=$1

docker run -it --rm --name rustscan rscan_original -r 1-65535 -a $TARGET -b 65535 -g  -- -Pn
