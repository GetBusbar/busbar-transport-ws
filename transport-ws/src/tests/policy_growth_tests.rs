// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::transport::guest_policy::{self, EXT_GUEST_POLICY};

fn admission() -> Admission {
    let policy = guest_policy::encode(7, 1, &[]).unwrap();
    let blob = extensions::encode(&[(EXT_GUEST_POLICY, &policy)]);
    Admission::new(Loans::from_initial(&blob).unwrap().unwrap(), 0)
}

#[test]
fn admission_fragmented_growth() {
    let mut admission = admission();
    let mut growths = 0;
    let mut moved = 0;
    for _ in 0..65536 {
        let previous = admission.opening.capacity();
        let length = admission.opening.len();
        admission.append(b"x");
        if admission.opening.capacity() != previous {
            growths += 1;
            moved += length;
        }
    }
    assert!(
        growths <= 16,
        "one-byte fragments caused {growths} reallocations"
    );
    assert!(moved <= 2 * 65536, "one header copied {moved} prefix bytes");
    assert_eq!(admission.opening.len(), 65536);
    assert!(admission.opening.iter().all(|byte| *byte == b'x'));
}

#[cfg(target_os = "linux")]
#[test]
fn admission_growth_wipes_the_replaced_secret_buffer() {
    const SECRET: &[u8] = b"admission-growth-secret";
    let mut admission = admission();
    admission.append(SECRET);
    crate::faults_tests::watch_free(admission.opening.as_ptr(), SECRET.len(), SECRET);
    let next = vec![b'x'; admission.opening.capacity()];
    admission.append(&next);
    crate::faults_tests::assert_freed_wiped();
    assert!(admission.opening.starts_with(SECRET));
}

#[test]
fn admission_parses_a_fragmented_head_only_after_its_terminator() {
    for ending in ["\r\n", "\n"] {
        let request = format!(
            "{ending}{ending}GET / HTTP/1.1{ending}X: {}{ending}{ending}",
            "x".repeat(60000)
        );
        let mut admission = admission();
        let mut calls = 0;
        let mut parsed_bytes = 0;
        for byte in request.bytes() {
            admission.append(&[byte]);
            if let Some(opening) = admission.complete_opening() {
                calls += 1;
                parsed_bytes += opening.len();
                assert!(Request::try_parse(opening).unwrap().is_some());
            }
        }
        assert_eq!(calls, 1);
        assert_eq!(parsed_bytes, request.len());
    }
}

#[test]
fn opening_refusal_status_is_checked_by_the_http_handshake_owner() {
    for status in [0, 99, 600, 70_123, u32::MAX] {
        assert!(
            refusal_wire(RefusalCopy {
                status,
                fields: Vec::new(),
                body: Vec::new(),
            })
            .is_err(),
            "{status}"
        );
    }
    let wire = refusal_wire(RefusalCopy {
        status: 403,
        fields: Vec::new(),
        body: b"denied".to_vec(),
    })
    .unwrap();
    assert!(wire.starts_with(b"HTTP/1.1 403 "));
    assert!(wire.ends_with(b"denied"));
}
