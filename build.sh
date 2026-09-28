#!/bin/sh
# build.sh
# Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
# SPDX-License-Identifier: MIT
# scspell-id: 00a84090-bb6e-11f1-ac18-80ee73e9b8e7
# shellcheck disable=SC2086

set -e

# Set `WATCOM` in your environment to the root of where you have Open
# Watcom V2 installed. We look for it in `/opt/watcom` by default.
# If it is not available DOS compilation will be skipped.

test -z "${WATCOM:-}" && export WATCOM="/opt/watcom"
export INCLUDE="${WATCOM:?}/h"
export PATH="${WATCOM:?}/binl64:${PATH:-}"

# Cleanup

test -x ./clean.sh || {
  printf '%s\n' "No executable ./clean.sh, aborting."
  exit 1
}

./clean.sh || :

# Open Watcom V2 DOS build

OWCC="$(command -v owcc)" || :

test -z "${CC:-}" && {
  CC="$(command -v c89   2> /dev/null \
     || command -v gcc   2> /dev/null \
     || command -v clang 2> /dev/null \
     || printf '%s\n' 'cc')"
}

test -d "${WATCOM:-}" && {
  test -d "${INCLUDE:-}" && {
    test -n "${OWCC:-}" && {
      CFLAGS="-std=c89 -bcom -march=i86 -fno-stack-check -mcmodel=t -frerun-optimizer -Os -s"

      printf '%s:' "${OWCC:?}"

      for i in ./*.c; do
        test -f "${i:-}" || continue
        b="${i%.c}"
        printf ' %s' "${b#./}"
        "${OWCC:?}" ${CFLAGS:?} -o "${i:?}om" "${i:?}"
      done

      printf '%s\n' ""

      rm -f ./*.sym ./*.o 2> /dev/null || :
    }
  }
}

# Native build

command -v "${CC:?}" > /dev/null 2>&1 && {
  CFLAGS="-std=c89 -Os -s"

  printf '%s:' "${CC:?}"

  for i in ./*.c; do
    test -f "${i:-}" || continue
    b="${i%.c}"
    printf ' %s' "${b#./}"
    "${CC:?}" ${CFLAGS:?} -o "${i%.c}" "${i:?}"
  done

  printf '%s\n' ""
}

# Done

exit 0
