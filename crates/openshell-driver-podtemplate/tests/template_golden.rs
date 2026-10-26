// SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
// SPDX-License-Identifier: Apache-2.0

//! Golden test for the workload pod that `mutate` builds from one representative
//! `PodTemplate`.
//!
//! `golden/fixture-template.json` holds a template that uses every field the driver
//! keeps and every field it replaces. `golden/fixture-pod.json` holds the workload pod
//! that template must produce with the parameters built by `params`. Each fixture is a
//! JSON object: its `spdx` member is the file's SPDX header, and its other member is the
//! value under test. Any drift in the produced pod fails the test.

use k8s_openapi::api::core::v1::PodTemplateSpec;
use openshell_driver_podtemplate::template::{MutationParams, mutate, validate};
use serde_json::Value;

const TEMPLATE_FIXTURE: &str = include_str!("golden/fixture-template.json");
const POD_FIXTURE: &str = include_str!("golden/fixture-pod.json");

/// Image that the golden template's sandbox container must name.
const SANDBOX_IMAGE: &str = "registry.example.com/agents/sandbox:1";

/// Returns the fixed parameters that the golden pod is built with.
fn params() -> MutationParams {
    MutationParams {
        name: "sandbox-golden".to_owned(),
        namespace: "agents".to_owned(),
        pair_label: "pair-golden".to_owned(),
        bootstrap_secret_name: "example-bootstrap".to_owned(),
        runtime_image: "registry.example.com/openshell/runtime:1".to_owned(),
        runtime_image_pull_policy: Some("Always".to_owned()),
        probe_helper_image: "registry.example.com/openshell/odp-probe:1".to_owned(),
        probe_helper_image_pull_policy: Some("IfNotPresent".to_owned()),
        boundary_port: 2222,
        uid: 1001,
        gid: 1002,
    }
}

/// Returns the value of the fixture's `member`.
fn fixture_member(fixture: &str, member: &str) -> Value {
    let document: Value = serde_json::from_str(fixture).expect("fixture is JSON");
    document
        .get(member)
        .cloned()
        .unwrap_or_else(|| panic!("fixture has no `{member}` member"))
}

#[test]
fn mutate_golden_pod_matches_fixture() {
    let template: PodTemplateSpec =
        serde_json::from_value(fixture_member(TEMPLATE_FIXTURE, "template"))
            .expect("fixture template is a PodTemplateSpec");
    let validated = validate(&template, SANDBOX_IMAGE).expect("golden template passes validate");

    let pod = mutate(&validated, &params());

    assert_eq!(
        serde_json::to_value(&pod).expect("pod serializes"),
        fixture_member(POD_FIXTURE, "pod")
    );
}
