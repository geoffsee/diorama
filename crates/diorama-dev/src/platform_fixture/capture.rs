use super::{
    BTreeMap, Options, Path, Result, alpine, digest, equal, fixture, guest, json, load,
    preparation, read, require, source_inventory,
};
#[allow(
    clippy::too_many_lines,
    reason = "Sequential ownership and immutable input preparation"
)]
pub(super) fn alpine(root: &Path, profile: &str, options: &Options) -> Result<u8> {
    let cancellation = crate::parity::process::Cancellation::default();
    let _signals = crate::parity::process::SignalGuard::install(cancellation.clone())?;
    let here = fixture(
        root,
        if profile == "alpine" {
            "alpine-preparation"
        } else {
            "alpine-rust-preparation"
        },
    );
    let inputs = load(&here.join("inputs.json"))?;
    let sources = source_inventory(root, profile)?;
    let cache = options.path("--input-cache")?;
    require(!cache.is_symlink(), "input cache symlink")?;
    let packages = inputs["packages"]["selected"]
        .as_object()
        .ok_or("package pins")?;
    for (name, pin) in packages {
        require(
            name.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+_.-".contains(&b)),
            "package basename",
        )?;
        equal(
            &json!(digest(&cache.join("packages").join(name))?),
            &pin["sha256"],
            "package pin",
        )?;
    }
    equal(
        &json!(digest(&cache.join("packages/APKINDEX.tar.gz"))?),
        &inputs["packages"]["index_sha256"],
        "index pin",
    )?;
    let artifact = if profile == "alpine" {
        let path = cache.join("preflight.test");
        equal(
            &json!(digest(&path)?),
            &inputs["oracle"]["binary_sha256"],
            "baseline oracle pin",
        )?;
        path
    } else {
        let directory = options.path("--artifact-directory")?;
        preparation::verify(root, directory)?;
        let metadata = load(&directory.join("artifact.json"))?;
        for key in ["sha256", "size", "target"] {
            equal(&metadata[key], &inputs["artifact"][key], "candidate pin")?;
        }
        let path = directory.join("dioramactl");
        equal(
            &json!(digest(&path)?),
            &inputs["artifact"]["sha256"],
            "actual Rust artifact",
        )?;
        path
    };
    let output = options.path("--output")?;
    let revision_logs = tempfile::tempdir()?;
    let revision_command = crate::parity::process::Commands {
        output: revision_logs.path().to_path_buf(),
        cancellation: cancellation.clone(),
    }
    .run(
        "source-revision",
        &[
            "git".into(),
            "-C".into(),
            root.into(),
            "rev-parse".into(),
            "HEAD".into(),
        ],
        std::time::Duration::from_secs(10),
        b"",
        true,
        4096,
    );
    if revision_command.as_ref().err().is_some_and(|error| {
        error
            .downcast_ref::<crate::parity::process::CommandFailure>()
            .is_some_and(|failure| !failure.cleanup_complete)
    }) {
        let _retained_logs = revision_logs.keep();
    }
    let revision = revision_command?.stdout.trim().to_owned();
    let baseline_directory = if profile == "alpine-rust" {
        Some(options.path("--baseline-directory")?)
    } else {
        None
    };
    let baseline = if let Some(directory) = baseline_directory {
        alpine::candidate_metadata(
            &load(&options.path("--artifact-directory")?.join("artifact.json"))?,
            &inputs,
            &revision,
        )?;
        Some(alpine::verified_baseline(root, directory, None)?)
    } else {
        None
    };
    let injection = options
        .values
        .get("--inject-failure")
        .map(|v| v.to_str().ok_or("injection UTF-8"))
        .transpose()?;
    require(
        injection.is_none_or(|v| ["setup", "test"].contains(&v)),
        "injection value",
    )?;
    let spec = guest::GuestSpec {
        output,
        image_cache: options.path("--image-cache")?,
        inputs: inputs.clone(),
        source_sha256: sources.clone(),
        revision,
        adapter: if profile == "alpine" {
            "qemu-disposable-alpine-preparation"
        } else {
            "qemu-disposable-alpine-rust-preparation"
        },
        injection,
    };
    let result = guest::capture(&spec, cancellation.clone(), |guest| {
        if let Some((_, digest)) = &baseline {
            guest.report["baseline_result_sha256"] = json!(digest);
        }
        let bundle = guest.private()?.join("bundle");
        let package_dir = bundle.join("repo/aarch64");
        std::fs::create_dir_all(&package_dir)?;
        let mut expected = BTreeMap::new();
        for (name, pin) in packages {
            std::fs::copy(cache.join("packages").join(name), package_dir.join(name))?;
            expected.insert(
                format!("repo/aarch64/{name}"),
                pin["sha256"].as_str().ok_or("package hash")?.to_owned(),
            );
        }
        std::fs::copy(
            cache.join("packages/APKINDEX.tar.gz"),
            package_dir.join("APKINDEX.tar.gz"),
        )?;
        expected.insert(
            "repo/aarch64/APKINDEX.tar.gz".into(),
            inputs["packages"]["index_sha256"]
                .as_str()
                .ok_or("index digest")?
                .into(),
        );
        let binary_name = if profile == "alpine" {
            "preflight.test"
        } else {
            "dioramactl"
        };
        std::fs::copy(&artifact, bundle.join(binary_name))?;
        expected.insert(binary_name.into(), digest(&artifact)?);
        if profile == "alpine-rust" {
            std::fs::copy(
                here.join("service-double.sh"),
                bundle.join("service-double.sh"),
            )?;
            expected.insert(
                "service-double.sh".into(),
                digest(&here.join("service-double.sh"))?,
            );
            archive_artifact(
                root,
                options.path("--artifact-directory")?,
                &output.join("artifact-build"),
            )?;
            guest.report["artifact_sha256"] = json!(digest(&artifact)?);
        }
        guest.upload_directory("copy-inputs", &bundle, "/tmp/diorama-bundle")?;
        let mut checks = String::new();
        for (name, hash) in expected {
            use std::fmt::Write as _;
            writeln!(&mut checks, "{hash}  {name}")?;
        }
        guest.remote(
            "verify-guest-inputs",
            &format!("cd /tmp/diorama-bundle && sha256sum -c - && chmod 0755 {binary_name}"),
            30,
            checks.as_bytes(),
            true,
        )?;
        let before = guest
            .remote(
                "baseline-inventory",
                "DIORAMA_RUN_PREPARATION=1 sh -s",
                if profile == "alpine" { 120 } else { 180 },
                &read(&here.join("guest.sh"), 256 * 1024)?,
                true,
            )?
            .stdout;
        guest.report["observation"] = json!(before);
        guest.reboot()?;
        let reboot = guest
            .remote(
                "reboot-verification",
                "sh -s",
                60,
                &read(&here.join("reboot.sh"), 256 * 1024)?,
                true,
            )?
            .stdout;
        if profile == "alpine" {
            alpine::baseline_semantic(&before, &reboot)?;
        } else {
            let effects = alpine::rust_semantic(root, &before, &reboot)?;
            let (expected, _) = baseline.as_ref().ok_or("verified baseline missing")?;
            alpine::baseline_parity(&effects, expected)?;
        }
        equal(
            &source_inventory(root, profile)?,
            &sources,
            "source stable through capture",
        )?;
        Ok(())
    });
    let mut report = result?;
    if report["status"] == "passed"
        && let Err(error) = alpine::verify_with_baseline(root, profile, output, baseline_directory)
    {
        report["status"] = json!("failed");
        report["errors"]
            .as_array_mut()
            .ok_or("capture errors")?
            .push(json!(error.to_string()));
    }
    guest::publish_cancellable(
        &output.join("result.json"),
        &mut report,
        &cancellation,
        false,
    )?;
    Ok(u8::from(report["status"] != "passed"))
}

fn archive_artifact(root: &Path, source: &Path, destination: &Path) -> Result<()> {
    preparation::verify(root, source)?;
    let qualification = load(&source.join("qualification.json"))?;
    let files = qualification["files"]
        .as_object()
        .ok_or("qualified artifact inventory")?;
    std::fs::create_dir(destination)?;
    for name in files
        .keys()
        .map(String::as_str)
        .chain(std::iter::once("qualification.json"))
    {
        require(
            Path::new(name).file_name().and_then(|n| n.to_str()) == Some(name),
            "artifact inventory basename",
        )?;
        std::fs::write(
            destination.join(name),
            read(&source.join(name), 32 * 1024 * 1024)?,
        )?;
    }
    preparation::verify(root, destination)?;
    Ok(())
}
