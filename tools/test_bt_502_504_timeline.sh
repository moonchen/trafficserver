#!/usr/bin/env bash
set -euo pipefail

# Lab-specific knobs:
ATS_ROOT="/opt/ats"
ATS_HTTP_PORT="8000"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Verifies bpftrace timeline behavior:
# 1) HTTP 200 requests are not emitted as timelines.
# 2) Multiple requests in close succession are handled.
# 3) 502/504 responses emit timelines.

ATS_PID="${ATS_PID:-$(pidof traffic_server || true)}"
if [[ -z "${ATS_PID}" ]]; then
  echo "FAIL: traffic_server is not running" >&2
  exit 1
fi

BPF_SCRIPT="${BPF_SCRIPT:-${SCRIPT_DIR}/origin-conn-timeline-502-504.bt}"
HARNESS="${HARNESS:-${SCRIPT_DIR}/origin_timeout_harness.py}"

URL_200="${URL_200:-http://127.0.0.1:${ATS_HTTP_PORT}/__ok200_bt}"
URL_502="${URL_502:-http://127.0.0.1:${ATS_HTTP_PORT}/__timeout502}"
URL_504="${URL_504:-http://127.0.0.1:${ATS_HTTP_PORT}/__timeout504}"

COUNT_200="${COUNT_200:-3}"
COUNT_502="${COUNT_502:-3}"
COUNT_504="${COUNT_504:-3}"

HARNESS_HOST="${HARNESS_HOST:-127.0.0.1}"
HARNESS_502_PORT="${HARNESS_502_PORT:-19002}"
HARNESS_504_PORT="${HARNESS_504_PORT:-19004}"
OK200_HOST="${OK200_HOST:-127.0.0.1}"
OK200_PORT="${OK200_PORT:-19010}"

TRACE_OUT="${TRACE_OUT:-/tmp/bt-502-504-test.out}"
HARNESS_LOG="${HARNESS_LOG:-/tmp/ats-origin-timeout-harness.log}"
OK200_LOG="${OK200_LOG:-/tmp/ats-origin-ok200.log}"

cleanup() {
  if [[ -n "${BT_PID:-}" ]]; then
    echo signal bpftrace child first
    if child="$(pgrep -P "${BT_PID}" bpftrace || true)"; then
      [[ -n "$child" ]] && sudo kill -INT "$child" 2>/dev/null || true
    fi
    echo then sudo wrapper
    sudo kill -INT "${BT_PID}" 2>/dev/null || true
    wait "${BT_PID}" 2>/dev/null || true
  fi
  if [[ -n "${HARNESS_PID:-}" ]] && kill -0 "${HARNESS_PID}" 2>/dev/null; then
    echo kill harness
    kill "${HARNESS_PID}" 2>/dev/null || true
    wait "${HARNESS_PID}" 2>/dev/null || true
  fi
  if [[ -n "${OK200_PID:-}" ]] && kill -0 "${OK200_PID}" 2>/dev/null; then
    echo kill 200 server
    kill "${OK200_PID}" 2>/dev/null || true
    wait "${OK200_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

rm -f "${TRACE_OUT}" "${HARNESS_LOG}"

echo Start a local always-200 origin.
rm -f "${OK200_LOG}"
python3 -m http.server "${OK200_PORT}" --bind "${OK200_HOST}" >"${OK200_LOG}" 2>&1 &
OK200_PID=$!

python3 "${HARNESS}" --host "${HARNESS_HOST}" --port-502 "${HARNESS_502_PORT}" --port-504 "${HARNESS_504_PORT}" \
  >"${HARNESS_LOG}" 2>&1 &
HARNESS_PID=$!

sleep 0.4

sudo bpftrace "${BPF_SCRIPT}" -p "${ATS_PID}" >"${TRACE_OUT}" 2>&1 &
BT_PID=$!

sleep 1.5

ok_200=0
pids=()

echo Burst 200 requests \(must all be 200 for this check to be meaningful\).
for _ in $(seq 1 "${COUNT_200}"); do
  (
    code="$(curl -sS -o /dev/null -w '%{http_code}' "${URL_200}")"
    if [[ "${code}" == "200" ]]; then
      exit 0
    fi
    echo "non-200 code from ${URL_200}: ${code}" >&2
    exit 1
  ) &
  pids+=($!)
done

echo Burst timeout paths in close succession.
for _ in $(seq 1 "${COUNT_502}"); do
  curl -sS -o /dev/null "${URL_502}" &
  pids+=($!)
done
for _ in $(seq 1 "${COUNT_504}"); do
  curl -sS -o /dev/null "${URL_504}" &
  pids+=($!)
done

for p in "${pids[@]}"; do
  if wait "${p}"; then
    :
  else
    echo "FAIL: one of the request workers failed" >&2
    exit 1
  fi
done

echo Allow final sm_finish events to flush.
sleep 2
cleanup

echo 1\) 200 filter check
if grep -q "status=200" "${TRACE_OUT}"; then
  echo "FAIL: found status=200 timeline in bpftrace output" >&2
  exit 1
fi

echo 2\) close-succession activity check
timeline_lines="$(rg -c '^--- sm_id=' "${TRACE_OUT}" || true)"
if [[ "${timeline_lines}" -lt 2 ]]; then
  echo "FAIL: expected multiple timelines from close-succession requests, got ${timeline_lines}" >&2
  exit 1
fi

echo 3\) 502/504 timeline coverage check
lines_502="$(rg -c '^--- sm_id=.*status=502' "${TRACE_OUT}" || true)"
lines_504="$(rg -c '^--- sm_id=.*status=504' "${TRACE_OUT}" || true)"
if [[ "${lines_502}" -lt "${COUNT_502}" ]]; then
  echo "FAIL: expected at least ${COUNT_502} 502 timelines, got ${lines_502}" >&2
  exit 1
fi
if [[ "${lines_504}" -lt "${COUNT_504}" ]]; then
  echo "FAIL: expected at least ${COUNT_504} 504 timelines, got ${lines_504}" >&2
  exit 1
fi

bad_status_lines="$(rg '^--- sm_id=' "${TRACE_OUT}" | rg -vc 'status=(502|504)' || true)"
if [[ "${bad_status_lines}" -ne 0 ]]; then
  echo "FAIL: found non-502/504 timeline header(s)" >&2
  exit 1
fi

echo "PASS"
echo "timelines total=${timeline_lines} status502=${lines_502} status504=${lines_504}"
echo "trace output: ${TRACE_OUT}"
echo "harness log:  ${HARNESS_LOG}"
