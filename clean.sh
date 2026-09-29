#!/bin/sh
# clean.sh
# Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
# SPDX-License-Identifier: MIT
# scspell-id: 07afb382-bb6e-11f1-8a1b-80ee73e9b8e7

set -e

rm -f ./*.sym ./*.o ./*.com 2> /dev/null || :

for i in ./*.c; do
  test -f "${i:-}" || continue
  rm -f "${i%.c}" 2> /dev/null || :
done

git clean -ndx 2> /dev/null || :

exit 0
