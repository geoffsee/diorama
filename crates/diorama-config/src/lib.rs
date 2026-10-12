//! KubeSolo-compatible versioned configuration decoding without host side effects.
mod model;
pub use model::*;
mod decode;
pub use decode::{
    ConfigError, DecodeLimits, DecodedConfig, ErrorKind, Presence, Warning, decode, decode_bytes,
    decode_with_limits, decode_yaml_value, decode_yaml_value_with_limits, read_file,
};
mod validate;
pub use validate::{
    HostContext, ValidatedConfig, ValidationWarning, normalize_image, resolve_runtime_endpoint,
};
mod runtime;
pub use runtime::{RuntimeEndpoint, RuntimePath, RuntimeProbe, RuntimeSettings};
mod inventory;
pub use inventory::{FIELDS, FieldSpec, FieldType};

mod layers;
pub use layers::{
    EnvironmentMode, ExplicitFlags, INPUT_BINDINGS, InputBinding, ParsedEnvironment,
    ResolutionWarning, ResolvedConfig, parse_environment, parse_setting, resolve_layers,
    resolve_parsed_layers,
};

mod render;
pub use render::render_effective_yaml;

mod persistence;
pub use persistence::{
    CleanupFailure, PersistenceError, PersistenceSource, PersistenceStage, WriteOutcome,
    write_document,
};

mod describe;
pub use describe::{SettingDescriptor, describe_settings};

pub mod api;
pub use api::{
    STRUCT_FIELD_PATHS, apply_merge_patch, apply_put_replacement, compute_etag, diff_configs,
    format_api_response, has_redacted_secrets, redact_secrets, serialize_api_config,
};

pub mod legacy;
pub use legacy::{
    ExtractedFlags, MigrationOutcome, extract_service_flags, flags_to_config, has_config_flag,
    migrate_service_flags, render_config_from_flags, rewrite_service_content, unquote_shell_value,
};

pub mod semver;
pub use semver::{
    MIN_CONFIG_FILE_VERSION, ParsedVersion, compare_versions, parse_version, supports_config_file,
};
