#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

import { readFileSync } from 'node:fs';
import { judge } from './parse-autobahn-report.mjs';

// An unrelated failure (or an unreadable report) does not prove that the existing negative leg
// caught its planted defect: truncating a non-empty echoed message. Keep the suite's grading
// rules in its one parser and require a recorded echo/UTF-8/message-size case to fail.
try {
  const { failures } = judge(JSON.parse(readFileSync(process.argv[2], 'utf8')));
  const caught = failures.some((failure) => failure.agent === 'broken'
    && failure.behavior === 'FAILED'
    && ['1.', '6.', '9.'].some((prefix) => failure.case.startsWith(prefix)));
  process.exitCode = caught ? 0 : 1;
} catch (error) {
  console.error(`negative control report could not be graded: ${error.message}`);
  process.exitCode = 1;
}
