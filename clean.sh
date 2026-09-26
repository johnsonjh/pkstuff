#!/bin/sh

set -e

rm -f ./*.sym ./*.o ./*.com 2> /dev/null || :

for i in ./*.c; do
  test -f "${i:-}" || continue
  rm -f "${i%.c}" 2> /dev/null || :
done

exit 0
