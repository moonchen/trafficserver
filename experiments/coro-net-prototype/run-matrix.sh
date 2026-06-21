#!/usr/bin/env bash
#
# Build and run the coro-net demos across the full {sanitizer} x {backend} grid.
#
# Each sanitizer is a separate CMake build dir (build-none / build-asan /
# build-tsan); within each, CTest runs every registered test once per available
# backend (epoll, and io_uring when liburing is present). Backends are therefore
# swept automatically — you never name them here.
#
# Usage:
#   ./run-matrix.sh                       # none, asan, tsan  x  all backends
#   ./run-matrix.sh --sanitizers none,tsan
#   ./run-matrix.sh --repeat 10           # run each test up to 10x (race hunting)
#   ./run-matrix.sh -L backend=uring      # ctest label filter (passed through)
#   ./run-matrix.sh -R coro_net_mt        # ctest name filter (passed through)
#
# Exit status is non-zero if any configuration fails.
set -uo pipefail
cd "$(dirname "$0")"

SANITIZERS=(none asan tsan)
REPEAT=1
CTEST_EXTRA=()

usage() { sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sanitizers) IFS=',' read -ra SANITIZERS <<< "$2"; shift 2 ;;
    --repeat)     REPEAT="$2"; shift 2 ;;
    -L|-R)        CTEST_EXTRA+=("$1" "$2"); shift 2 ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

command -v cmake >/dev/null || { echo "error: cmake not found" >&2; exit 1; }
JOBS="$(nproc 2>/dev/null || echo 4)"

declare -A RESULT
overall=0

for san in "${SANITIZERS[@]}"; do
  bdir="build-${san}"
  echo "==================================================================="
  echo "### SANITIZER=${san} :: configure + build (${bdir})"
  echo "==================================================================="
  mkdir -p "${bdir}"
  if ! cmake -S . -B "${bdir}" -DSANITIZER="${san}" >"${bdir}/configure.log" 2>&1; then
    echo "  CONFIGURE FAILED — see ${bdir}/configure.log"; tail -n 15 "${bdir}/configure.log"
    RESULT[$san]="CONFIG-FAIL"; overall=1; continue
  fi
  grep -E "SANITIZER=|backends:" "${bdir}/configure.log" | sed 's/^-- /  /'
  if ! cmake --build "${bdir}" -j"${JOBS}" >"${bdir}/build.log" 2>&1; then
    echo "  BUILD FAILED — see ${bdir}/build.log"; tail -n 20 "${bdir}/build.log"
    RESULT[$san]="BUILD-FAIL"; overall=1; continue
  fi

  echo "### SANITIZER=${san} :: ctest (repeat until-fail:${REPEAT})"
  if ctest --test-dir "${bdir}" --output-on-failure \
           --repeat "until-fail:${REPEAT}" "${CTEST_EXTRA[@]}"; then
    RESULT[$san]="PASS"
  else
    RESULT[$san]="TEST-FAIL"; overall=1
  fi
  echo
done

echo "========================= MATRIX SUMMARY ========================="
for san in "${SANITIZERS[@]}"; do
  printf "  %-6s : %s\n" "${san}" "${RESULT[$san]:-SKIP}"
done
echo "=================================================================="
[[ ${overall} -eq 0 ]] && echo "ALL GREEN" || echo "FAILURES PRESENT"
exit "${overall}"
