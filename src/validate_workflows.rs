//! Rust port of the retired `scripts/validate_workflows.py`.
//!
//! Zero-Error CI workflow validator for the Tor-Bridges-Collector / TorShield-IR
//! repository. It enforces, identically to the Python original:
//!
//!   1. Every file under `.github/workflows/` is valid YAML.
//!   2. No `run:` step on a Linux runner invokes a *hardcoded* `powershell` or
//!      `pwsh` binary as a command (the root cause of incident #73 / Exit 127,
//!      since `powershell` is absent on GitHub's ubuntu runners). Explicit
//!      `shell: pwsh` declarations are permitted by the policy and are NOT
//!      flagged.
//!   3. Reports a per-file and total violation count and exits non-zero on any
//!      violation, so it can gate CI.
//!
//! The YAML layer is `serde_yaml` (already a workspace dependency) instead of
//! PyYAML; all matching rules, message shapes and exit codes are preserved.

use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde_yaml::Value;

/// Shell connectors stripped from the start of a logical line before the
/// powershell check, identical to `_CONNECTORS` in the Python original.
const CONNECTORS: &[&str] = &["&&", "||", ";", "|", "(", "`", ">"];

/// Reproduce `_line_invokes_powershell` from the Python original.
///
/// A `powershell`/`pwsh` *command* token: the first non-whitespace token on a
/// logical line (after stripping shell connectors like `&&` / `||` / `;` /
/// `|` / `(` / `` ` ``), immediately followed by an argument boundary. This
/// deliberately does NOT match the words "powershell"/"pwsh" appearing inside
/// prose such as `echo "... no powershell"` or inside `#` comments.
pub fn line_invokes_powershell(raw_line: &str) -> bool {
    let mut line = raw_line.trim().to_string();
    if line.is_empty() || line.starts_with('#') {
        return false;
    }
    // Peel off leading shell connectors so `&& powershell ...` is caught.
    loop {
        let mut changed = false;
        for &sep in CONNECTORS {
            if line.starts_with(sep) {
                line = line[sep.len()..].trim_start().to_string();
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    // Same pattern as Python: re.match(r"(powershell|pwsh)([\s.\-]|$)", line, re.I)
    let re = Regex::new(r"(?i)^(powershell|pwsh)([\s.\-]|$)")
        .expect("static powershell pattern must compile");
    re.is_match(&line)
}

/// Reproduce `_is_linux_runner`: a string `runs-on` starting (case-folded)
/// with `ubuntu`, `linux` or `self-hosted` is Linux; anything else that is
/// not a plain string (matrix expression, list) is conservatively treated as
/// Linux too.
pub fn is_linux_runner(runs_on: Option<&Value>) -> bool {
    if let Some(Value::String(name)) = runs_on {
        let lower = name.to_lowercase();
        return lower.starts_with("ubuntu")
            || lower.starts_with("linux")
            || lower.starts_with("self-hosted");
    }
    true
}

/// Reproduce Python `repr()` for the single-line strings embedded in
/// violation messages (`{raw_line.strip()!r}`).
fn py_repr(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

fn string_field<'a>(mapping: &'a serde_yaml::Mapping, key: &str) -> Option<&'a Value> {
    mapping.get(Value::String(key.to_string()))
}

/// Return the list of human-readable violation strings for one workflow
/// file, mirroring `validate_file(path)` in the Python original.
pub fn validate_file(path: &str) -> Vec<String> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) => return vec![format!("{path}: unreadable -> {err}")],
    };
    let doc: Value = match serde_yaml::from_str(&text) {
        Ok(doc) => doc,
        Err(err) => return vec![format!("{path}: invalid YAML -> {err}")],
    };
    let mapping = match doc.as_mapping() {
        Some(mapping) => mapping.clone(),
        None => return vec![format!("{path}: top-level YAML is not a mapping")],
    };
    let jobs = match string_field(&mapping, "jobs").and_then(Value::as_mapping) {
        Some(jobs) => jobs.clone(),
        None => return vec![format!("{path}: 'jobs' is missing or not a mapping")],
    };

    let mut violations = Vec::new();
    for (job_key, job) in &jobs {
        let Some(job_map) = job.as_mapping() else {
            continue; // reusable workflow calls (workflow_call) have no steps/runs-on
        };
        let job_name = job_key.as_str().unwrap_or_default().to_string();
        let linux = is_linux_runner(string_field(job_map, "runs-on"));
        let steps = match string_field(job_map, "steps").and_then(Value::as_sequence) {
            Some(steps) => steps.clone(),
            None => continue,
        };
        for step in &steps {
            let Some(step_map) = step.as_mapping() else {
                continue;
            };
            let Some(Value::String(run_text)) = string_field(step_map, "run") else {
                continue;
            };
            for raw_line in run_text.lines() {
                if !line_invokes_powershell(raw_line) {
                    continue;
                }
                let shell = match string_field(step_map, "shell") {
                    Some(Value::String(shell)) => shell.to_lowercase(),
                    _ => String::new(),
                };
                if shell == "pwsh" {
                    // Explicit pwsh shell is permitted by the policy.
                    continue;
                }
                let step_name = match string_field(step_map, "name") {
                    Some(Value::String(name)) => name.clone(),
                    _ => "<run>".to_string(),
                };
                let location = if linux {
                    "linux runner"
                } else {
                    "non-linux runner"
                };
                violations.push(format!(
                    "{path}: job '{job_name}' step '{step_name}' invokes hardcoded \
                     powershell/pwsh on a {location}: {}",
                    py_repr(raw_line.trim())
                ));
            }
        }
    }
    violations
}

/// List `*.yml` + `*.yaml` files directly under `root` (non-recursive), sorted,
/// mirroring `sorted(glob(root/*.yml) + glob(root/*.yaml))`.
pub fn workflow_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if path.is_file() && (name.ends_with(".yml") || name.ends_with(".yaml")) {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Execute the validator over `root`, printing the exact report format of the
/// Python original, and return the process exit code.
pub fn run(root: &Path) -> i32 {
    let paths = workflow_files(root);
    if paths.is_empty() {
        println!(
            "validate_workflows: no workflow files found under {}",
            root.display()
        );
        return 1;
    }

    let mut total = 0_u64;
    for path in &paths {
        let display = path.display().to_string();
        let violations = validate_file(&display);
        total += violations.len() as u64;
        let status = if violations.is_empty() { "OK" } else { "FAIL" };
        println!("[{status}] {display}");
        for msg in &violations {
            println!("        - {msg}");
        }
    }

    println!(
        "\nValidated {} workflow file(s); {total} violation(s).",
        paths.len()
    );
    if total == 0 {
        0
    } else {
        1
    }
}

/// CLI entry point: `validate_workflows [dir]` (default `.github/workflows`),
/// mirroring `main(sys.argv)` in the Python original.
pub fn entry(args: &[String]) -> i32 {
    let root = args
        .get(1)
        .map(String::as_str)
        .unwrap_or(".github/workflows");
    run(Path::new(root))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_hardcoded_powershell() {
        assert!(line_invokes_powershell("powershell -File x.ps1"));
        assert!(line_invokes_powershell("pwsh -c 'ls'"));
        assert!(line_invokes_powershell("PowerShell -NoProfile a.ps1"));
        assert!(line_invokes_powershell("&& powershell.exe -File x.ps1"));
        assert!(line_invokes_powershell("| pwsh -c foo"));
    }

    #[test]
    fn ignores_prose_and_comments() {
        assert!(!line_invokes_powershell("# powershell is absent on linux"));
        assert!(!line_invokes_powershell(
            "echo \"there is no powershell here\""
        ));
        assert!(!line_invokes_powershell(""));
        assert!(!line_invokes_powershell("   "));
        // A trailing comma is not an argument boundary ([\s.\-]|$ required).
        assert!(!line_invokes_powershell("pwsh, not-a-command"));
    }

    #[test]
    fn linux_runner_detection() {
        assert!(is_linux_runner(Some(&Value::String(
            "ubuntu-latest".into()
        ))));
        assert!(is_linux_runner(Some(&Value::String("Ubuntu-22.04".into()))));
        assert!(is_linux_runner(Some(&Value::String("linux-x64".into()))));
        assert!(is_linux_runner(Some(&Value::String("self-hosted".into()))));
        assert!(!is_linux_runner(Some(&Value::String(
            "windows-latest".into()
        ))));
        assert!(!is_linux_runner(Some(&Value::String("macos-14".into()))));
        // A matrix expression is a *string* in YAML; Python's isinstance()
        // check applies the same startswith() test to it, so it does NOT
        // match the Linux prefixes (the conservative fallback only covers
        // non-string shapes such as lists and missing keys).
        let matrix = Value::String("${{ matrix.os }}".into());
        assert!(!is_linux_runner(Some(&matrix)));
        assert!(is_linux_runner(None));
        let list = Value::Sequence(vec![
            Value::String("self-hosted".into()),
            Value::String("gpu".into()),
        ]);
        assert!(is_linux_runner(Some(&list)));
    }

    #[test]
    fn validate_file_reports_violation_shape() {
        let dir = std::env::temp_dir().join(format!("vf_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let file = dir.join("bad.yml");
        let yaml = "name: t\n'on': push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - name: broken\n        run: powershell -File x.ps1\n";
        std::fs::write(&file, yaml).expect("write workflow");
        let violations = validate_file(&file.display().to_string());
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("job 'build' step 'broken'"));
        assert!(violations[0].contains("linux runner"));
        assert!(violations[0].ends_with("'powershell -File x.ps1'"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn explicit_pwsh_shell_is_permitted() {
        let dir = std::env::temp_dir().join(format!("vf_pwsh_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let file = dir.join("ok.yml");
        let yaml = "name: t\n'on': push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - shell: pwsh\n        run: pwsh -c 'ls'\n";
        std::fs::write(&file, yaml).expect("write workflow");
        assert!(validate_file(&file.display().to_string()).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_yaml_and_shape_guards() {
        let dir = std::env::temp_dir().join(format!("vf_inv_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let bad = dir.join("broken.yml");
        std::fs::write(&bad, "jobs: [unclosed\n").expect("write");
        let violations = validate_file(&bad.display().to_string());
        assert!(violations[0].contains("invalid YAML"));
        let scalar = dir.join("scalar.yml");
        std::fs::write(&scalar, "just a string\n").expect("write");
        let violations = validate_file(&scalar.display().to_string());
        assert!(violations[0].contains("top-level YAML is not a mapping"));
        let nojobs = dir.join("nojobs.yml");
        std::fs::write(&nojobs, "name: x\n").expect("write");
        let violations = validate_file(&nojobs.display().to_string());
        assert!(violations[0].contains("'jobs' is missing or not a mapping"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// v2.6.0: Regression test asserting Cloudflare providers 1..11 each
    /// expose the structural triplet (CF_ACCOUNT_ID_N / CF_API_TOKEN_N /
    /// CF_AI_GATEWAY_URL_N) in the ai_self_healing workflow. The test
    /// parses the YAML structure but never resolves or prints secret values.
    #[test]
    fn cloudflare_provider_triplet_completeness() {
        let wf_path = ".github/workflows/ai_self_healing.yml";
        let text = std::fs::read_to_string(wf_path).expect("ai_self_healing.yml must exist");
        let doc: serde_yaml::Value =
            serde_yaml::from_str(&text).expect("ai_self_healing.yml must be valid YAML");
        let mapping = doc.as_mapping().expect("top-level must be a mapping");
        let jobs = mapping
            .get(&serde_yaml::Value::String("jobs".into()))
            .and_then(|v| v.as_mapping())
            .expect("jobs must be a mapping");

        // Find the auto-diagnose-and-fix job.
        let auto_job = jobs
            .get(&serde_yaml::Value::String("auto-diagnose-and-fix".into()))
            .and_then(|v| v.as_mapping())
            .expect("auto-diagnose-and-fix job must exist");
        let steps = auto_job
            .get(&serde_yaml::Value::String("steps".into()))
            .and_then(|v| v.as_sequence())
            .expect("steps must be a sequence");

        // Find the Run AutoDebugEngine step by inspecting each step's env.
        let mut provider_vars: std::collections::BTreeMap<u32, Vec<String>> =
            std::collections::BTreeMap::new();
        for step in steps {
            let sm = step.as_mapping().expect("step must be a mapping");
            let env = sm
                .get(&serde_yaml::Value::String("env".into()))
                .and_then(|v| v.as_mapping());
            if env.is_none() {
                continue;
            }
            for (k, _v) in env.unwrap() {
                let key = k.as_str().unwrap_or_default();
                // Only track CF_ prefixed vars.
                if !key.starts_with("CF_") {
                    continue;
                }
                // Extract provider index: CF_ACCOUNT_ID_<N>, CF_API_TOKEN_<N>,
                // CF_AI_GATEWAY_URL_<N>.
                if let Some(idx_str) = key.rsplit('_').next() {
                    if let Ok(idx) = idx_str.parse::<u32>() {
                        if (1..=11).contains(&idx) {
                            let base = key.trim_end_matches(&format!("_{idx}"));
                            provider_vars.entry(idx).or_default().push(base.to_string());
                        }
                    }
                }
            }
        }

        // Assert: each provider 1..11 has exactly 3 vars.
        let required = vec!["CF_ACCOUNT_ID", "CF_API_TOKEN", "CF_AI_GATEWAY_URL"];
        for i in 1..=11_u32 {
            let vars = provider_vars.get(&i);
            assert!(
                vars.is_some(),
                "Cloudflare provider {i}: no CF_ env vars found in auto-diagnose-and-fix env"
            );
            let vars = vars.unwrap();
            for req in &required {
                assert!(
                    vars.contains(&req.to_string()),
                    "Cloudflare provider {i}: missing {req}_{i} in auto-diagnose-and-fix env"
                );
            }
            assert_eq!(
                vars.len(),
                3,
                "Cloudflare provider {i}: expected exactly 3 vars (got {:?})",
                vars
            );
        }
    }

    #[test]
    fn workflow_files_globs_and_sorts() {
        let dir = std::env::temp_dir().join(format!("vf_glob_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(dir.join("b.yml"), "").expect("write");
        std::fs::write(dir.join("a.yaml"), "").expect("write");
        std::fs::write(dir.join("c.txt"), "").expect("write");
        let names: Vec<String> = workflow_files(&dir)
            .iter()
            .map(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            })
            .collect();
        assert_eq!(names, vec!["a.yaml", "b.yml"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
