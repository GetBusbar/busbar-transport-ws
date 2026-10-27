#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# The `ws` suite of testing/conformance/suites.tsv: Autobahn|Testsuite (RFC 6455) through this repo's OWN
# harness (testing/ws-conformance), in the three legs, and one verdict:
#   1. CONTROL           the strict std-only reference echo peer       (run.sh --control)
#   2. NEGATIVE CONTROL  the deliberately broken echo peer, MUST be red (run.sh --negative-control)
#   3. SUBJECT           busbar's ws door at $BUSBAR_CHECKOUT (the pin) (run.sh --subject)
# All three always run. `pass` only when all three hold; a subject that cannot be built or booted is
# `fail` (armed). Writes $CONFORMANCE_OUT/verdict.json. Needs docker, node 22 and rust on PATH.
set -uo pipefail
: "${CONFORMANCE_OUT:?}" "${BUSBAR_CHECKOUT:?}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
H="$repo/testing/ws-conformance"
RUN="$H/scripts/run.sh"
say() { printf 'ws: %s\n' "$*" >&2; }

# The subject's build tree, once, against busbar at the pin.
W="$(mktemp -d "${TMPDIR:-/tmp}/ws-conf.XXXXXX")"; trap 'rm -rf "$W"' EXIT
WS_SUBJECT_MANIFEST="$("$H/scripts/subject-manifest.sh" "$W/subject")" || { say "the subject build tree could not be written"; WS_SUBJECT_MANIFEST=""; }
export WS_SUBJECT_MANIFEST

# The broken peer needs the harness's one npm dependency, from the lockfile (integrity-pinned).
npm_rc=0
(cd "$H" && npm ci --ignore-scripts --no-audit --no-fund) >&2 || npm_rc=$?

rm -rf "$H/reports"
c_rc=0; n_rc=0; s_rc=0
say "=== leg 1: control"; bash "$RUN" --control >&2 || c_rc=$?
say "=== leg 2: negative control"
if [ "$npm_rc" -ne 0 ]; then say "npm ci failed ($npm_rc): the broken peer cannot start"; n_rc=$npm_rc; else bash "$RUN" --negative-control >&2 || n_rc=$?; fi
say "=== leg 3: subject"
if [ -z "$WS_SUBJECT_MANIFEST" ]; then s_rc=1; else bash "$RUN" --subject >&2 || s_rc=$?; fi
say "legs: control=$c_rc negative-control=$n_rc subject=$s_rc"

python3 -I - "$c_rc" "$n_rc" "$s_rc" "$H/reports" "$CONFORMANCE_OUT/verdict.json" <<'PY'
import json, sys, os
c, n, s, reports, out = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5]
def leg(tag):
    try: return json.load(open(os.path.join(reports, tag, "verdict.json")))
    except Exception: return {}
cv, sv = leg("control"), leg("subject")
why = []
if c == 3 or n == 3 or s == 3: why.append("docker is unavailable, so Autobahn could not run")
else:
    if c != 0 or cv.get("status") != "pass": why.append(f"the control leg did not pass (exit {c}, verdict {cv.get('status')})")
    if n != 0: why.append(f"the negative control was not graded red as required (exit {n})")
    if s != 0 or sv.get("status") != "pass": why.append(f"the subject leg did not pass (exit {s}, verdict {sv.get('status')}); see reports/subject")
v = {"suite": "ws", "status": "fail" if why else "pass", "armed": True,
     "standard": sv.get("standard") or cv.get("standard") or "RFC 6455 WebSocket Protocol (Autobahn|Testsuite)",
     "plan": sv.get("plan") or cv.get("plan") or "Autobahn|Testsuite fuzzingclient, full default case set",
     "spec_version": sv.get("spec_version") or cv.get("spec_version") or "autobahn-testsuite 0.8.2"}
if why: v["reason"] = "; ".join(why)
json.dump(v, open(out, "w"), indent=2); open(out, "a").write("\n")
print(json.dumps(v))
sys.exit(1 if why else 0)
PY
