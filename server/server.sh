#!/bin/bash
ulimit -c 0
export NODE_OPTIONS="--secure-heap=16 --max-old-space-size=512"
exec node server.js