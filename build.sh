#!/bin/sh
# shellcheck disable=SC2086

set -e

test -z "${WATCOM:-}" && export WATCOM="/opt/watcom"
export INCLUDE="${WATCOM:?}/h"
export PATH="${WATCOM:?}/binl64:${PATH:-}"

test -x ./clean.sh || {
  printf '%s\n' "No executable ./clean.sh, aborting."
  exit 1
}

./clean.sh || :

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

exit 0
