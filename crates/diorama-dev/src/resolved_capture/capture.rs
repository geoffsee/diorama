use super::directory;
use crate::{
    Result,
    defaults::{
        capture::{self, OwnedDocker, Runner},
        load, require,
    },
    json,
};
use serde_json::json as value;
pub fn cli(args: &[String]) -> Result<i32> {
    let args = capture::parse_args(args)?;
    let fixture = directory();
    let inputs = load(&fixture.join("inputs.json"))?;
    capture::validate_archives(&inputs, &args)?;
    capture::create_output(&args.output)?;
    let mut owned = OwnedDocker {
        tag: capture::owned_tag("diorama-resolved-")?,
        image_id: None,
        containers: Vec::new(),
    };
    let mut report = value!({"schema_version":2,"inputs":inputs,"source_sha256":capture::source_inventory(&fixture)?,"image":owned.tag,"containers":[],"errors":[],"cleanup_errors":[]});
    let mut runner = Runner::with_signals(&args.output)?;
    let result = (|| -> Result<()> {
        capture::build(
            &mut runner,
            &owned,
            &fixture,
            &args,
            &inputs,
            &["main.go", "Dockerfile"],
        )?;
        report["image_inspect"] = capture::inspect_image(&mut runner, &mut owned)?;
        let mut records = Vec::new();
        for index in 0..2 {
            let name = format!("{}-{index}", owned.tag);
            owned.containers.push(name.clone());
            let label = format!("run{index}");
            let raw = runner.bounded(
                &capture::run_args(&owned, &name, index, None),
                &label,
                90,
                2 * 1024 * 1024,
            )?;
            let record = extract_record(&raw)?;
            let value = json::parse(record.as_bytes())?;
            capture::write_json(&args.output.join(format!("{label}.json")), &value)?;
            records.push(record);
        }
        require(records[0] == records[1], "completion was nondeterministic")?;
        report["identical_repeats"] = value!(true);
        report["output_sha256"] = value!({"run0.json":capture::digest(&args.output.join("run0.json"))?,"run1.json":capture::digest(&args.output.join("run1.json"))?});
        let source = format!("{}:/out/modules.sha256", owned.containers[0]);
        let mut copy = capture::arguments(&["docker", "cp", &source]);
        copy.push(
            args.output
                .canonicalize()?
                .join("modules.sha256")
                .into_os_string(),
        );
        runner.bounded(&copy, "copy-modules", 30, 1024 * 1024)?;
        report["modules_sha256"] = value!(capture::digest(&args.output.join("modules.sha256"))?);
        crate::defaults::evidence::verify_modules(
            &crate::read_bounded(&args.output.join("modules.sha256"), 1024 * 1024)?,
            &report,
            true,
        )?;
        require(
            report["source_sha256"] == capture::source_inventory(&fixture)?,
            "capture sources changed during execution",
        )?;
        Ok(())
    })();
    if let Err(error) = result {
        capture::push_error(&mut report, "errors", error.to_string());
    }
    report["containers"] = value!(owned.containers);
    report["image_id"] = value!(owned.image_id);
    runner.finish(&mut report, &args.output, &owned)?;
    Ok(i32::from(!capture::successful(&report)))
}
pub(crate) fn extract_record(raw: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(raw)?;
    let records = text
        .lines()
        .filter_map(|line| line.strip_prefix("DIORAMA_RESOLVED="))
        .collect::<Vec<_>>();
    require(records.len() == 1, "missing or duplicate capture record")?;
    json::parse(records[0].as_bytes())?;
    Ok(records[0].to_owned())
}
