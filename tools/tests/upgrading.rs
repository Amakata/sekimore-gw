//! UPGRADING.md and UPGRADING.ja.md have been reviewed up to the gateway the base image takes
//! (was base/scripts/check-upgrading.py); then the rule on files broken on purpose.

use sekimore_tools::checks::upgrading::{marker_problem, pinned, DOCKERFILE, FILES};
use sekimore_tools::repo_root;

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

#[test]
fn upgrading_covers_the_gateway_the_base_image_takes() {
    let pinned = pinned(&read(DOCKERFILE)).unwrap();
    let problems: Vec<String> = FILES
        .iter()
        .filter_map(|f| marker_problem(f, &read(f), &pinned))
        .collect();
    assert!(problems.is_empty(), "{}", problems.join("\n\n"));
}

const DOCKERFILE_TEXT: &str =
    "ARG SEKIMORE_GW_IMAGE=ghcr.io/example/gateway:0.3.0-alpha.4\nFROM ${SEKIMORE_GW_IMAGE} AS gw\n";

#[test]
fn it_reads_the_version_the_image_takes() {
    assert_eq!(pinned(DOCKERFILE_TEXT).unwrap(), "0.3.0-alpha.4");
    assert_eq!(
        pinned("FROM x\nARG SEKIMORE_GW_IMAGE=gw:0.2.79  \n").unwrap(),
        "0.2.79"
    );
}

#[test]
fn it_fails_without_the_pinned_image() {
    for bad in [
        "FROM scratch\n",
        "ARG SEKIMORE_GW_IMAGE=gw\n",
        "ARG SEKIMORE_GW_IMAGE=gw:latest\n",
        "  ARG SEKIMORE_GW_IMAGE=gw:0.2.79\n",
    ] {
        assert!(pinned(bad).is_err(), "{bad}");
    }
}

#[test]
fn it_passes_a_marker_at_or_past_the_version() {
    for marker in ["0.3.0-alpha.4", "0.3.0-alpha.10", "0.3.0", "0.3.1"] {
        let text = format!("<!-- reviewed-up-to: {marker} -->\n# Upgrading\n");
        assert_eq!(
            marker_problem("UPGRADING.md", &text, "0.3.0-alpha.4"),
            None,
            "{marker}"
        );
    }
}

#[test]
fn it_fails_a_marker_out_of_date() {
    for marker in ["0.3.0-alpha.3", "0.3.0-alpha", "0.2.79", "0.2.100"] {
        let text = format!("<!-- reviewed-up-to: {marker} -->\n# Upgrading\n");
        let p = marker_problem("UPGRADING.md", &text, "0.3.0-alpha.4");
        assert!(
            p.as_deref()
                .is_some_and(|p| p.contains("move the marker to 0.3.0-alpha.4")),
            "{marker}"
        );
    }
}

#[test]
fn it_fails_a_file_that_does_not_start_with_the_marker() {
    for text in [
        "",
        "# Upgrading\n<!-- reviewed-up-to: 0.3.0 -->\n",
        " <!-- reviewed-up-to: 0.3.0 -->\n",
        "<!-- reviewed-up-to: latest -->\n",
    ] {
        let p = marker_problem("UPGRADING.ja.md", text, "0.3.0");
        assert!(
            p.as_deref().is_some_and(|p| p.contains("must start with")),
            "{text:?}"
        );
    }
}
