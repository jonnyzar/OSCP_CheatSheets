#!/bin/bash

#creates persistent listener for reverse shell
#arguments: $1: port
sudo socat TCP4-LISTEN:$1,reuseaddr,fork,ignoreeof STDOUT
