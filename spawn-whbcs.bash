#!/bin/sh -e

if [ "$BASH_SOURCE" ]
then
  cd "$(dirname "$BASH_SOURCE")"
else
  cd "$(dirname "$0")"
fi

[ "$WHBCS_CLOSEFDS" ] && exec </dev/null >/dev/null 2>&1

touch whbcs.log

if [ "$1" = "-f" ]
then
  exec ./whbcs.py --logfile whbcs.log 2>>whbcs.log
else
  setsid ./whbcs.py --logfile whbcs.log 2>>whbcs.log &
  [ "$1" = "-b" ] || tail -f whbcs.log
fi
