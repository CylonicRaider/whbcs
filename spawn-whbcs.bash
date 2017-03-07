#!/bin/sh -e

if [ "$BASH_SOURCE" ]
then
  cd "$(dirname "$BASH_SOURCE")"
else
  cd "$(dirname "$0")"
fi

touch whbcs.log

if [ "$1" = "-f" ]
then
  exec ./whbcs.py --logfile whbcs.log 2>>whbcs.log
else
  setsid ./whbcs.py --logfile whbcs.log 2>>whbcs.log &
  [ "$1" = "-b" ] || tail -f whbcs.log
fi
