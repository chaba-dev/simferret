use std::fs;
use std::path::{Path, PathBuf};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root should exist")
}

fn read(relative: &str) -> String {
    fs::read_to_string(repository_root().join(relative))
        .unwrap_or_else(|error| panic!("failed to read {relative}: {error}"))
}

fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn adoc_section(text: &str, title: &str) -> String {
    let heading = format!("== {title}");
    let lines = text
        .lines()
        .skip_while(|line| *line != heading)
        .skip(1)
        .take_while(|line| !line.starts_with("== "))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!lines.is_empty(), "missing AsciiDoc section: {title}");
    normalized(&lines)
}

#[test]
fn rfd_index_metadata_and_checklists_are_consistent() {
    let root = repository_root();
    let rfd_root = root.join("rfd");
    let index = read("rfd/README.adoc");

    assert!(!rfd_root.join("README.md").exists());

    for entry in fs::read_dir(&rfd_root).expect("rfd directory should be readable") {
        let entry = entry.expect("RFD entry should be readable");
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !entry.path().is_dir()
            || name.len() != 4
            || !name.chars().all(|character| character.is_ascii_digit())
        {
            continue;
        }

        let document = entry.path().join("README.adoc");
        assert!(document.is_file(), "RFD {name} must use README.adoc");
        assert!(
            index.contains(&format!("link:{name}/README.adoc[")),
            "RFD {name} must be linked from the index"
        );

        let implementation_count = ["IMPLEMENTATION.org", "IMPLEMENTATION.md"]
            .iter()
            .filter(|filename| entry.path().join(filename).is_file())
            .count();
        assert_eq!(
            implementation_count, 1,
            "RFD {name} must have exactly one implementation checklist"
        );

        let text = fs::read_to_string(document).expect("RFD document should be readable");
        let state = text
            .lines()
            .find_map(|line| line.strip_prefix(":state: "))
            .expect("RFD must declare state");
        let discussion = text
            .lines()
            .find_map(|line| line.strip_prefix(":discussion:"))
            .expect("RFD must declare discussion metadata")
            .trim();
        if state == "discussion" {
            assert!(
                discussion.starts_with("https://github.com/chaba-dev/simferret/pull/"),
                "RFD {name} in discussion must link its pull request"
            );
        }
    }
}

#[test]
fn implementation_checklists_use_phase_terminology() {
    for path in ["rfd/0001/IMPLEMENTATION.org", "rfd/0002/IMPLEMENTATION.org"] {
        let text = read(path);
        let has_gate = text
            .split(|character: char| !character.is_ascii_alphabetic())
            .any(|word| matches!(word.to_ascii_lowercase().as_str(), "gate" | "gates"));
        assert!(!has_gate, "{path} must use phase terminology");
    }
}

#[test]
fn replay_contract_identifies_builds_outage_and_semantic_outcome() {
    let architecture = read("rfd/0001/README.adoc");
    let identity = adoc_section(&architecture, "Replay identity");
    assert!(
        identity.contains(
            "SimFerret and QEMU executable digests or immutable Nix derivation identities"
        )
    );

    let proof_of_concept = read("rfd/0002/README.adoc");
    for section in ["Assertions", "Acceptance criteria"] {
        let outage = adoc_section(&proof_of_concept, section);
        assert!(outage.contains("request attempt"));
        assert!(outage.contains("server is stopped"));
        assert!(outage.contains("failed or unavailable"));
    }

    let determinism = adoc_section(&proof_of_concept, "Determinism contract");
    assert!(determinism.contains("semantic outcome digest"));
    assert!(!determinism.contains("final state digest"));

    let artifacts = adoc_section(&proof_of_concept, "Artifacts");
    assert!(artifacts.contains("matching content-addressed external QEMU"));
    assert!(artifacts.contains("semantic outcome digest"));
}

#[test]
fn implementation_ownership_and_development_entry_points_are_explicit() {
    let implementation = normalized(&read("rfd/0001/IMPLEMENTATION.org"));
    assert!(implementation.contains("[X] Create the Rust workspace"));
    assert!(implementation.contains("RFD 2 owns implementation progress and evidence"));
    assert!(!implementation.contains("Pin and record a QEMU version"));

    let index = normalized(&read("rfd/README.adoc"));
    assert!(index.contains("the implementation checklist must use exactly one"));

    let readme = normalized(&read("README.md"));
    for command in [
        "nix --extra-experimental-features 'nix-command flakes' develop",
        "nix --extra-experimental-features 'nix-command flakes' flake check",
        ".agents/dev cargo fmt --all -- --check",
        ".agents/dev cargo clippy --locked --workspace --all-targets --all-features -- --deny warnings",
        ".agents/dev cargo test --locked --workspace --all-targets --all-features",
        "bash -n .agents/dev .agents/setup",
        ".agents/dev jj status",
    ] {
        assert!(readme.contains(command), "README must document {command}");
    }
}

#[test]
fn setup_has_safe_platform_and_identity_boundaries() {
    let setup = read(".agents/setup");
    assert!(setup.contains("uname -s"));
    assert!(setup.contains("uname -m"));
    assert!(setup.contains("refusing to change its ownership"));
    assert!(setup.contains("git config --get user.name"));
    assert!(setup.contains("git config --get user.email"));
    assert!(!setup.contains("git show"));
    assert!(!setup.contains(".bash_profile"));
    assert_eq!(setup.matches("jj metaedit --update-author").count(), 1);
    assert!(normalized(&setup).contains(
        "if [[ \"$created_jj\" == true ]]; then .agents/dev jj metaedit --update-author fi"
    ));

    assert!(normalized(&setup).contains(
        "if [[ ! -x \"$nix_bin\" ]]; then if [[ \"$(uname -s)\" != \"Linux\" || \"$(uname -m)\" != \"x86_64\" ]]; then"
    ));

    let identity = setup
        .find("jj_user_name=")
        .expect("setup must resolve identity");
    let initialization = setup
        .find("jj git init --colocate")
        .expect("setup must initialize Jujutsu");
    assert!(
        identity < initialization,
        "identity must precede JJ initialization"
    );
}

#[test]
fn ci_actions_are_pinned_and_cargo_checks_are_locked() {
    let ci = read(".github/workflows/ci.yml");
    let commits = read(".github/workflows/commits.yml");

    let mut action_count = 0;
    for workflow in [&ci, &commits] {
        for line in workflow.lines().map(str::trim) {
            let Some(action) = line
                .strip_prefix("- uses: ")
                .or_else(|| line.strip_prefix("uses: "))
            else {
                continue;
            };
            action_count += 1;
            let revision = action
                .split_once('@')
                .unwrap_or_else(|| panic!("action must include a revision: {action}"))
                .1
                .split_whitespace()
                .next()
                .expect("action revision should exist");
            assert_eq!(revision.len(), 40, "action must use a full commit SHA");
            assert!(
                revision
                    .chars()
                    .all(|character| character.is_ascii_hexdigit()),
                "action must use a hexadecimal commit SHA"
            );
        }
    }

    assert_eq!(action_count, 7, "test must inspect every action reference");
    assert_eq!(ci.matches("nix-2.35.1/install").count(), 3);
    assert!(ci.contains("cargo clippy --locked"));
    assert!(ci.contains("cargo test --locked"));
}
