#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// Reads Autobahn|Testsuite's `index.json` (the fuzzingclient's per-agent, per-case summary) and
// decides pass/fail, then (optionally) writes a `verdict.json` in the schema
// `docs/design/... CONFORMANCE-SYNC-DESIGN.md` §2 defines for every conformance suite's
// aggregator to publish.
//
// THE RULE: any case whose `behavior` is not `OK` is RED, with one allow-listed exception
// (`INFORMATIONAL` — Autobahn's own "no verdict, informational only" cases, e.g. reserved-bits
// cases some peers legitimately treat differently). `NON-STRICT` is RED, not a warning: it means
// the peer diverged from the strict reading of the spec, and a suite that treated that as a pass
// would be grading on a curve nobody asked for.
//
// `UNIMPLEMENTED` IS A THIRD BUCKET, NEITHER PASS NOR FAIL. This suite's claim
// (`conformance/registry.toml`) is RFC 6455 alone; Autobahn's default case set also drives its
// separate permessage-deflate module (RFC 7692, case groups 12/13), and a peer that never
// negotiates that extension is correctly scored `UNIMPLEMENTED` there, not `OK` and not `FAILED`.
// Counting it as a pass would claim an extension busbar never negotiated; counting it as a
// failure would fail an RFC 6455 suite over a spec it never claims to pass; EXCLUDING those cases
// from the run would hide the day busbar starts answering the extension's handshake and regresses
// on it. So they are judged, reported by name, and never move `ok`.
//
// FLOOR: an empty report (no agents, or an agent with zero cases) is RED. A suite that returns
// vacuously green over a run that tested nothing is the exact failure mode
// `testing/verdict-covers-every-leg.py`'s docstring is about, one level down: the aggregator
// trusted a leg that "passed" by not running.

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ALLOWED_BEHAVIORS = new Set(['OK', 'INFORMATIONAL']);
const UNCLAIMED_BEHAVIORS = new Set(['UNIMPLEMENTED']);
// UNIMPLEMENTED is unclaimed only for the permessage-deflate groups; on any other case it is a failure.
const isDeflateCase = (caseId) => caseId.startsWith('12.') || caseId.startsWith('13.');

/**
 * @param {object} report Autobahn's parsed `index.json`.
 * @returns {{ ok: boolean, totalCases: number, failures: Array<{agent:string, case:string, behavior:string}>, unimplemented: Array<{agent:string, case:string, behavior:string}> }}
 */
export function judge(report) {
  const failures = [];
  const unimplemented = [];
  let totalCases = 0;
  let emptyAgent = false;
  const agents = Object.keys(report ?? {});
  for (const agent of agents) {
    const cases = report[agent] ?? {};
    if (Object.keys(cases).length === 0) {
      emptyAgent = true;
    }
    for (const [caseId, result] of Object.entries(cases)) {
      totalCases += 1;
      const behavior = result?.behavior ?? 'MISSING';
      if (ALLOWED_BEHAVIORS.has(behavior)) {
        continue;
      }
      if (UNCLAIMED_BEHAVIORS.has(behavior) && isDeflateCase(caseId)) {
        unimplemented.push({ agent, case: caseId, behavior });
        continue;
      }
      // Its duration and closing behaviour, as Autobahn recorded them: a case that ran out of time
      // reads differently from one the peer answered wrongly.
      failures.push({
        agent,
        case: caseId,
        behavior,
        duration: result?.duration,
        behaviorClose: result?.behaviorClose,
      });
    }
  }
  // FLOOR: zero agents, or an agent that ran zero cases, is refused rather than accepted.
  if (agents.length === 0 || totalCases === 0 || emptyAgent) {
    failures.push({ agent: '(none)', case: '(none)', behavior: 'EMPTY_REPORT' });
  }
  return { ok: failures.length === 0, totalCases, failures, unimplemented };
}

/**
 * status:"pass" is permitted only if the run judged something AND every subject leg was armed.
 * @param {boolean} armed
 * @param {boolean} ok `judge(report).ok`
 * @returns {'pass'|'fail'|'not-run'}
 */
export function decideStatus(armed, ok) {
  return armed && ok ? 'pass' : armed ? 'fail' : 'not-run';
}

export function buildVerdict({ status, armed, commit, runId, evidence, generatedAt }) {
  return {
    schema: 'busbar.conformance.verdict/1',
    suite: 'ws',
    standard: 'RFC 6455 WebSocket Protocol (Autobahn|Testsuite)',
    plan: 'Autobahn|Testsuite fuzzingclient, full default case set',
    spec_version: 'autobahn-testsuite 0.8.2',
    status,
    armed,
    commit: commit ?? null,
    run_id: runId ?? null,
    evidence: evidence ?? null,
    generated_at: generatedAt ?? new Date().toISOString(),
  };
}

function main(argv) {
  if (argv.includes('--selftest')) {
    return selftest();
  }
  const reportIdx = argv.indexOf('--report');
  const outIdx = argv.indexOf('--out');
  if (reportIdx === -1) {
    console.error('usage: parse-autobahn-report.mjs --report <index.json> [--out verdict.json] [--armed true|false] [--commit sha] [--run-id url] [--evidence uri]');
    return 2;
  }
  const reportPath = argv[reportIdx + 1];
  let report;
  try {
    report = JSON.parse(readFileSync(reportPath, 'utf8'));
  } catch (e) {
    console.error(`could not read/parse ${reportPath}: ${e.message}`);
    report = null;
  }
  const { ok, totalCases, failures, unimplemented } = report
    ? judge(report)
    : { ok: false, totalCases: 0, failures: [{ agent: '(none)', case: '(none)', behavior: 'UNREADABLE_REPORT' }], unimplemented: [] };
  const armedArg = (argv[argv.indexOf('--armed') + 1] ?? 'false') === 'true';
  const commit = argv.includes('--commit') ? argv[argv.indexOf('--commit') + 1] : undefined;
  const runId = argv.includes('--run-id') ? argv[argv.indexOf('--run-id') + 1] : undefined;
  const evidence = argv.includes('--evidence') ? argv[argv.indexOf('--evidence') + 1] : undefined;

  const status = decideStatus(armedArg, ok);
  const verdict = buildVerdict({ status, armed: armedArg, commit, runId, evidence });

  console.log(`ws-conformance: ${totalCases} case(s) judged, ${failures.length} failure(s), ${unimplemented.length} unimplemented (not claimed)`);
  for (const f of failures.slice(0, 50)) {
    const timing = f.duration === undefined ? '' : ` (${f.duration} ms, close ${f.behaviorClose ?? '?'})`;
    console.log(`  RED  ${f.agent} :: ${f.case} -> ${f.behavior}${timing}`);
  }
  for (const u of unimplemented.slice(0, 50)) {
    console.log(`  SKIP ${u.agent} :: ${u.case} -> ${u.behavior} (extension not negotiated, not claimed by this suite)`);
  }
  if (outIdx !== -1) {
    writeFileSync(argv[outIdx + 1], JSON.stringify(verdict, null, 2) + '\n');
  }
  return status === 'pass' ? 0 : 1;
}

function selftest() {
  let checks = 0;
  let failures = 0;
  const check = (holds, okMsg, missMsg) => {
    checks += 1;
    if (holds) {
      console.log(`  ok: ${okMsg}`);
    } else {
      console.log(`  MISS: ${missMsg}`);
      failures += 1;
    }
  };

  const good = judge({
    firefox: {
      '1.1.1': { behavior: 'OK' },
      '1.1.2': { behavior: 'INFORMATIONAL' },
    },
  });
  check(good.ok, 'an all-OK report is accepted', 'an all-OK report was refused');

  const bad = judge({
    firefox: {
      '1.1.1': { behavior: 'OK' },
      '2.1.1': { behavior: 'FAILED' },
    },
  });
  check(!bad.ok, 'a report containing FAILED is refused', 'a report containing FAILED was accepted');

  // UNIMPLEMENTED (permessage-deflate cases against a peer that never negotiates the extension)
  // must neither fail the suite nor vanish silently -- it is reported, by name, as its own bucket.
  const unimpl = judge({
    busbar: {
      '1.1.1': { behavior: 'OK' },
      '12.1.1': { behavior: 'UNIMPLEMENTED' },
    },
  });
  check(unimpl.ok, 'an UNIMPLEMENTED case does not fail the suite', 'an UNIMPLEMENTED case failed the suite');
  check(
    unimpl.unimplemented.length === 1 && unimpl.unimplemented[0].case === '12.1.1',
    'an UNIMPLEMENTED case is reported by name',
    'an UNIMPLEMENTED case was not reported in its own bucket',
  );

  const nonStrict = judge({ firefox: { '3.1.1': { behavior: 'NON-STRICT' } } });
  check(!nonStrict.ok, 'a NON-STRICT case is refused (no curve)', 'a NON-STRICT case was accepted');

  const empty = judge({});
  check(!empty.ok, 'an empty report is refused (FLOOR)', 'an empty report (zero agents) was accepted -- FLOOR did not bite');

  const emptyCases = judge({ firefox: {} });
  check(!emptyCases.ok, 'an agent with zero cases is refused (FLOOR)', 'an agent with zero cases was accepted -- FLOOR did not bite');

  // FLOOR, per agent: an agent with cases must not carry an agent that ran none.
  const oneEmptyAgent = judge({ a: { '1.1.1': { behavior: 'OK' } }, b: {} });
  check(!oneEmptyAgent.ok, 'a report with one zero-case agent is refused (FLOOR, per agent)', 'a report with one zero-case agent was accepted -- FLOOR did not bite');

  // UNIMPLEMENTED is the permessage-deflate bucket (groups 12/13) only; elsewhere it is a failure.
  const coreUnimpl = judge({ a: { '1.1.1': { behavior: 'UNIMPLEMENTED' }, '2.1.1': { behavior: 'UNIMPLEMENTED' } } });
  check(!coreUnimpl.ok && coreUnimpl.unimplemented.length === 0, 'UNIMPLEMENTED outside groups 12/13 is a failure', 'UNIMPLEMENTED on core (non-12/13) cases was accepted');
  const deflateUnimpl = judge({ a: { '13.7.18': { behavior: 'UNIMPLEMENTED' }, '12.1.1': { behavior: 'UNIMPLEMENTED' }, '1.1.1': { behavior: 'OK' } } });
  check(deflateUnimpl.ok && deflateUnimpl.unimplemented.length === 2, 'UNIMPLEMENTED on groups 12/13 stays in its own bucket', 'UNIMPLEMENTED on groups 12/13 was not kept in its own bucket');

  // The armed/status contract: unarmed can never be "pass", regardless of the report. This calls the
  // decision main() uses, over a good report.
  check(decideStatus(false, good.ok) === 'not-run', 'an unarmed run over a good report is not-run, never pass', `an unarmed run over a good report decided status=${decideStatus(false, good.ok)}, want not-run`);
  check(
    decideStatus(true, good.ok) === 'pass' && decideStatus(true, bad.ok) === 'fail',
    'an armed run decides pass over a good report and fail over a bad one',
    'an armed run did not decide pass over a good report and fail over a bad one',
  );

  if (failures) {
    console.error(`\n${failures} selftest fixture(s) did not behave as declared`);
    return 1;
  }
  console.log(`selftest: ${checks} fixture(s) passed`);
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exit(main(process.argv.slice(2)));
}
