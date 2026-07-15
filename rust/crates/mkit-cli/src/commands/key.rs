//! `mkit key` keystore management commands.

use std::io::Write as _;
use std::path::Path;

use clap::{Parser, Subcommand};
use mkit_keystore::{
    Algorithm, BackendKind, Capabilities, GenerateOptions, ImportOptions, KeyAttrs, KeyLabel,
    KeyRef, KeySelector, Keystore, SecretKey, open_backend,
};
use zeroize::Zeroize;

use crate::clap_shim;
use crate::config::{self, Config};
use crate::exit;

#[derive(Debug, Parser)]
#[command(name = "mkit key", about = "Manage keystore signing keys.")]
struct KeyOpts {
    #[command(subcommand)]
    command: KeyCommand,
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    /// Generate a new signing key.
    Generate(GenerateOpts),
    /// List keys visible to a backend.
    List(ListOpts),
    /// Import 32-byte signing key material.
    Import(ImportOpts),
    /// Export extractable signing key material.
    Export(ExportOpts),
    /// Delete exactly one signing key.
    Delete(DeleteOpts),
}

#[derive(Debug, Parser)]
#[allow(clippy::struct_excessive_bools)]
struct GenerateOpts {
    #[arg(long, value_name = "BACKEND")]
    backend: Option<String>,
    #[arg(long, value_name = "LABEL")]
    label: Option<String>,
    #[arg(long, value_name = "ALG")]
    algorithm: Option<String>,
    #[arg(long, conflicts_with = "non_extractable")]
    extractable: bool,
    #[arg(long, conflicts_with = "extractable")]
    non_extractable: bool,
    #[arg(long)]
    device_bound: bool,
    #[arg(long)]
    require_user_presence: bool,
    #[arg(long)]
    force: bool,
    #[arg(long)]
    print_pubkey: bool,
    /// BLS12-381 threshold (M-of-N): quorum required to recover an
    /// aggregated signature. Required with
    /// `--algorithm bls12381-thr`.
    #[arg(long, value_name = "M")]
    threshold: Option<u32>,
    /// BLS12-381 threshold total (N): number of shares the dealer
    /// produces. Required with `--algorithm bls12381-thr`.
    #[arg(long, value_name = "N")]
    total: Option<u32>,
}

#[derive(Debug, Parser)]
struct ListOpts {
    #[arg(long, value_name = "BACKEND")]
    backend: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
#[allow(clippy::struct_excessive_bools)]
struct ImportOpts {
    #[arg(long, value_name = "ALG")]
    algorithm: Option<String>,
    #[arg(long, value_name = "BACKEND")]
    backend: Option<String>,
    #[arg(long, value_name = "LABEL")]
    label: Option<String>,
    #[arg(long, value_name = "HEX")]
    hex: Option<String>,
    #[arg(long, value_name = "PATH")]
    file: Option<String>,
    #[arg(long, conflicts_with = "non_extractable")]
    extractable: bool,
    #[arg(long, conflicts_with = "extractable")]
    non_extractable: bool,
    #[arg(long)]
    device_bound: bool,
    #[arg(long)]
    require_user_presence: bool,
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Parser)]
struct ExportOpts {
    #[arg(long, value_name = "BACKEND")]
    backend: Option<String>,
    #[arg(long, value_name = "LABEL")]
    label: Option<String>,
    #[arg(long, value_name = "ALG")]
    algorithm: Option<String>,
    #[arg(long)]
    unsafe_print_secret: bool,
}

#[derive(Debug, Parser)]
struct DeleteOpts {
    #[arg(long, value_name = "BACKEND")]
    backend: Option<String>,
    #[arg(long, value_name = "LABEL")]
    label: Option<String>,
    #[arg(long, value_name = "ALG")]
    algorithm: Option<String>,
    #[arg(long)]
    yes: bool,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<KeyOpts>("mkit key", args) {
        Ok(opts) => opts,
        Err(code) => return code,
    };
    match opts.command {
        KeyCommand::Generate(opts) => generate(opts),
        KeyCommand::List(opts) => list(opts),
        KeyCommand::Import(opts) => import(opts),
        KeyCommand::Export(opts) => export(opts),
        KeyCommand::Delete(opts) => delete(opts),
    }
}

fn generate(opts: GenerateOpts) -> u8 {
    let cfg = match read_config() {
        Ok(cfg) => cfg,
        Err(code) => return code,
    };
    let algorithm = match optional_algorithm_or_default(opts.algorithm.as_deref()) {
        Ok(algorithm) => algorithm,
        Err(code) => return code,
    };

    // BLS12-381 threshold needs a trusted-dealer ceremony: one
    // command produces N encrypted shares stored under
    // `<label>-<index>`, plus prints the cohort public key + keyid for
    // registration in trust-roots. The `--threshold` / `--total`
    // flags are required and `--extractable` / `--non-extractable` /
    // `--device-bound` / `--require-user-presence` do not apply (the
    // share record carries its own metadata, not the generic
    // `KeyAttrs`).
    #[cfg(feature = "bls-threshold")]
    if algorithm == Algorithm::Bls12381Threshold {
        return generate_bls_threshold(&cfg, &opts);
    }

    let attrs = attrs_from_flags(
        opts.extractable,
        opts.non_extractable,
        opts.device_bound,
        opts.require_user_presence,
    );
    let selection = match selection_for(&cfg, opts.backend, opts.label, Some(algorithm)) {
        Ok(selection) => selection,
        Err(code) => return code,
    };
    let store = match store_for_backend(selection.backend) {
        Ok(store) => store,
        Err(code) => return code,
    };
    let label = match KeyLabel::new(selection.label.clone()) {
        Ok(label) => label,
        Err(error) => return keystore_error(error),
    };
    let Some(generator) = store.generator() else {
        return keystore_error(mkit_keystore::Error::UnsupportedOperation("generate"));
    };
    let signer = match generator.generate(
        &label,
        algorithm,
        attrs,
        GenerateOptions {
            overwrite: opts.force,
        },
    ) {
        Ok(signer) => signer,
        Err(error) => return keystore_error(error),
    };
    let metadata = match signer.metadata() {
        Ok(metadata) => metadata,
        Err(error) => return keystore_error(error),
    };
    print_metadata(&metadata);
    print_capabilities(&store.capabilities());
    if opts.print_pubkey {
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{}", metadata.keyid());
    }
    exit::OK
}

/// Trusted-dealer keygen for the BLS12-381 threshold cohort. Stores
/// `total` encrypted shares under `<label>-<index>` in the chosen
/// keystore root and prints the aggregated cohort public key + keyid
/// so the caller can register it in their `trust-roots.toml`.
///
/// The planned multi-host distribution ceremony (release-party CLI)
/// replaces the single-host trusted dealer; the keystore-side API is
/// unchanged.
#[cfg(feature = "bls-threshold")]
#[allow(clippy::too_many_lines)]
fn generate_bls_threshold(cfg: &Config, opts: &GenerateOpts) -> u8 {
    use commonware_codec::Encode as _;
    use mkit_attest::BLS_THRESHOLD_KEYID_PREFIX;
    use mkit_keystore::SoftwareKeystore;

    let Some(total) = opts.total else {
        return emit_err(
            "mkit key generate --algorithm bls12381-thr requires --total N",
            exit::USAGE,
        );
    };
    let Some(threshold) = opts.threshold else {
        return emit_err(
            "mkit key generate --algorithm bls12381-thr requires --threshold M",
            exit::USAGE,
        );
    };
    let Some(total_nz) = core::num::NonZeroU32::new(total) else {
        return emit_err("--total must be at least 1", exit::USAGE);
    };
    if threshold == 0 || threshold > total {
        return emit_err(
            "--threshold M must satisfy 1 <= M <= N (--total)",
            exit::USAGE,
        );
    }
    // The single-host trusted dealer pins the N3f1 fault model, which
    // fixes `threshold = ceil(2n/3)`. We accept the caller's
    // `--threshold` so the CLI surface matches the spec wording, but
    // we validate it against what the dealer will actually produce —
    // otherwise the caller would silently get a different threshold
    // than they asked for.
    let dealer_threshold = mkit_attest::bls_threshold_for(total);
    if threshold != dealer_threshold {
        return emit_err(
            &format!(
                "--threshold {threshold} does not match the N3f1 quorum for --total {total} \
                 (expected {dealer_threshold}); the single-host trusted dealer pins this ratio. \
                 Arbitrary M-of-N will be accepted once a DKG protocol is wired in."
            ),
            exit::USAGE,
        );
    }

    let backend = match opts.backend.as_deref() {
        Some(b) => match parse_backend(b) {
            Ok(parsed) => parsed,
            Err(code) => return code,
        },
        None => match parse_backend(cfg.key.backend_or_fallback()) {
            Ok(parsed) => parsed,
            Err(code) => return code,
        },
    };
    if !matches!(backend, BackendKind::Software) {
        return emit_err(
            &format!(
                "BLS threshold shares are currently stored only by the `software` backend; \
                 `--backend {backend}` is not supported"
            ),
            exit::USAGE,
        );
    }
    let base_label = match opts.label.as_deref() {
        Some(label) => label.to_owned(),
        None => {
            return emit_err(
                "mkit key generate --algorithm bls12381-thr requires --label <BASE>",
                exit::USAGE,
            );
        }
    };

    // Run the trusted dealer with the OS RNG. The cohort `Sharing`
    // gives us the aggregated public key + every holder's `Share`.
    // `SysRng`'s `TryRng::Error` is fallible (`getrandom::Error`);
    // `UnwrapErr` gives the infallible `CryptoRng` the dealer expects,
    // panicking only if the OS random source itself fails.
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let (sharing, shares) = mkit_attest::bls_threshold_trusted_dealer(&mut rng, total_nz);
    let agg_pubkey = sharing.public().encode().to_vec();
    let keyid = format!("{BLS_THRESHOLD_KEYID_PREFIX}{}", hex_lower(&agg_pubkey));

    let Ok(store) = SoftwareKeystore::new() else {
        return emit_err("software keystore root not discoverable", exit::UNAVAILABLE);
    };

    let mut stored: Vec<(String, u32)> = Vec::with_capacity(shares.len());
    for (offset, share) in shares.iter().enumerate() {
        // commonware-cryptography's `Share` has a `u32` index; we use
        // `offset` (0..total) as the CLI-visible holder index so the
        // emitted labels are `<base>-0` through `<base>-{N-1}`.
        let share_index = u32::try_from(offset).unwrap_or(u32::MAX);
        let label_str = format!("{base_label}-{share_index}");
        let label = match KeyLabel::new(label_str.clone()) {
            Ok(l) => l,
            Err(error) => return keystore_error(error),
        };
        let share_bytes = share.encode().to_vec();
        if let Err(error) = store.store_bls_share(
            &label,
            &share_bytes,
            agg_pubkey.clone(),
            share_index,
            threshold,
            total,
            keyid.clone(),
            opts.force,
        ) {
            return keystore_error(error);
        }
        stored.push((label_str, share_index));
    }

    // Report. The cohort public key + keyid go to stdout so it's
    // pipeable into `mkit config` / `trust-roots.toml`; the
    // human-readable share roster goes to stderr.
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "generated {total} BLS12-381 threshold shares ({threshold}-of-{total} quorum)"
    );
    for (label, index) in &stored {
        let _ = writeln!(stderr, "  share {index}: software:{label}");
    }
    let _ = writeln!(stderr, "register the cohort public key under this keyid:");

    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{keyid}");
    if opts.print_pubkey {
        let _ = writeln!(stdout, "pubkey_hex = {}", hex_lower(&agg_pubkey));
    }
    exit::OK
}

fn list(opts: ListOpts) -> u8 {
    let cfg = match read_config() {
        Ok(cfg) => cfg,
        Err(code) => return code,
    };
    let backend = match parse_backend(
        &opts
            .backend
            .unwrap_or_else(|| cfg.key.backend_or_fallback().to_owned()),
    ) {
        Ok(backend) => backend,
        Err(code) => return code,
    };
    let store = match store_for_backend(backend) {
        Ok(store) => store,
        Err(code) => return code,
    };
    let Some(lister) = store.lister() else {
        return keystore_error(mkit_keystore::Error::UnsupportedOperation("list"));
    };
    let mut keys = match lister.list() {
        Ok(keys) => keys,
        Err(error) => return keystore_error(error),
    };
    let capabilities = store.capabilities();
    keys.sort_by(|left, right| {
        (left.backend(), left.label(), left.algorithm()).cmp(&(
            right.backend(),
            right.label(),
            right.algorithm(),
        ))
    });
    let mut stdout = std::io::stdout().lock();
    if opts.json {
        let _ = write!(stdout, "[");
        for (index, key) in keys.iter().enumerate() {
            if index > 0 {
                let _ = write!(stdout, ",");
            }
            let _ = write!(
                stdout,
                "{{\"backend\":\"{}\",\"label\":\"{}\",\"algorithm\":\"{}\",\"keyid\":\"{}\",\"extractable\":{},\"require_user_presence\":{},\"device_bound\":{},\"capabilities\":{}}}",
                key.backend(),
                json_escape(key.label()),
                key.algorithm(),
                json_escape(key.keyid()),
                key.extractable,
                key.require_user_presence,
                key.device_bound,
                json_capabilities(&capabilities)
            );
        }
        let _ = writeln!(stdout, "]");
    } else {
        for key in keys {
            let _ = writeln!(
                stdout,
                "{} {} {} {} extractable={} user_presence={} device_bound={} can_generate={} can_import={} can_export={} can_delete={} supports_listing={} supports_user_presence={} supports_device_bound={} supports_non_extractable={}",
                key.backend(),
                key.label(),
                key.algorithm(),
                key.keyid(),
                key.extractable,
                key.require_user_presence,
                key.device_bound,
                capabilities.can_generate,
                capabilities.can_import,
                capabilities.can_export,
                capabilities.can_delete,
                capabilities.supports_listing,
                capabilities.supports_user_presence,
                capabilities.supports_device_bound,
                capabilities.supports_non_extractable
            );
        }
    }
    exit::OK
}

fn import(opts: ImportOpts) -> u8 {
    let cfg = match read_config() {
        Ok(cfg) => cfg,
        Err(code) => return code,
    };
    let Some(algorithm) = opts.algorithm.as_deref() else {
        return emit_err("mkit key import requires --algorithm", exit::USAGE);
    };
    let algorithm = match parse_algorithm(algorithm) {
        Ok(algorithm) => algorithm,
        Err(code) => return code,
    };
    if opts.hex.is_some() == opts.file.is_some() {
        return emit_err(
            "mkit key import requires exactly one of --hex or --file",
            exit::USAGE,
        );
    }
    let attrs = attrs_from_flags(
        opts.extractable,
        opts.non_extractable,
        opts.device_bound,
        opts.require_user_presence,
    );
    let selection = match selection_for(&cfg, opts.backend, opts.label, Some(algorithm)) {
        Ok(selection) => selection,
        Err(code) => return code,
    };
    let mut secret = match (opts.hex, opts.file) {
        (Some(hex), None) => match parse_secret_hex(&hex) {
            Ok(secret) => secret,
            Err(code) => return code,
        },
        (None, Some(file)) => match mkit_core::sign::load_raw_32(Path::new(&file)) {
            Ok(secret) => *secret,
            Err(error) => return emit_err(&format!("read key file: {error}"), exit::DATAERR),
        },
        _ => unreachable!(),
    };
    let wrapped = SecretKey::new(algorithm, secret);
    secret.zeroize();
    let store = match store_for_backend(selection.backend) {
        Ok(store) => store,
        Err(code) => return code,
    };
    let label = match KeyLabel::new(selection.label) {
        Ok(label) => label,
        Err(error) => return keystore_error(error),
    };
    let Some(importer) = store.importer() else {
        return keystore_error(mkit_keystore::Error::UnsupportedOperation("import"));
    };
    let signer = match importer.import(
        &label,
        wrapped,
        attrs,
        ImportOptions {
            overwrite: opts.force,
        },
    ) {
        Ok(signer) => signer,
        Err(error) => return keystore_error(error),
    };
    match signer.metadata() {
        Ok(metadata) => {
            print_metadata(&metadata);
            exit::OK
        }
        Err(error) => keystore_error(error),
    }
}

fn export(opts: ExportOpts) -> u8 {
    let cfg = match read_config() {
        Ok(cfg) => cfg,
        Err(code) => return code,
    };
    let algorithm = match optional_algorithm(opts.algorithm.as_deref()) {
        Ok(algorithm) => algorithm,
        Err(code) => return code,
    };
    if !opts.unsafe_print_secret {
        return emit_err(
            "mkit key export requires --unsafe-print-secret",
            exit::USAGE,
        );
    }
    let selection = match selection_for(&cfg, opts.backend, opts.label, algorithm) {
        Ok(selection) => selection,
        Err(code) => return code,
    };
    let store = match store_for_backend(selection.backend) {
        Ok(store) => store,
        Err(code) => return code,
    };
    let selector = match KeySelector::new(selection.label, algorithm) {
        Ok(selector) => selector,
        Err(error) => return keystore_error(error),
    };
    let Some(exporter) = store.exporter() else {
        return keystore_error(mkit_keystore::Error::UnsupportedOperation("export"));
    };
    let secret = match exporter.export(&selector) {
        Ok(secret) => secret,
        Err(error) => return keystore_error(error),
    };
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "warning: printing secret key material to stdout");
    let mut stdout = std::io::stdout().lock();
    if let Err(error) = writeln!(stdout, "{}", hex_lower(secret.expose_secret())) {
        return emit_err(&format!("write exported secret: {error}"), exit::CANTCREAT);
    }
    exit::OK
}

fn delete(opts: DeleteOpts) -> u8 {
    let cfg = match read_config() {
        Ok(cfg) => cfg,
        Err(code) => return code,
    };
    let algorithm = match optional_algorithm(opts.algorithm.as_deref()) {
        Ok(algorithm) => algorithm,
        Err(code) => return code,
    };
    if !opts.yes {
        return emit_err("mkit key delete requires --yes", exit::USAGE);
    }
    let selection = match selection_for(&cfg, opts.backend, opts.label, algorithm) {
        Ok(selection) => selection,
        Err(code) => return code,
    };
    let store = match store_for_backend(selection.backend) {
        Ok(store) => store,
        Err(code) => return code,
    };
    let selector = match KeySelector::new(selection.label.clone(), algorithm) {
        Ok(selector) => selector,
        Err(error) => return keystore_error(error),
    };
    let Some(deleter) = store.deleter() else {
        return keystore_error(mkit_keystore::Error::UnsupportedOperation("delete"));
    };
    match deleter.delete(&selector) {
        Ok(()) => {
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "deleted {}:{}", selection.backend, selection.label);
            exit::OK
        }
        Err(error) => keystore_error(error),
    }
}

#[derive(Debug)]
struct Selection {
    backend: BackendKind,
    label: String,
}

fn selection_for(
    cfg: &Config,
    backend: Option<String>,
    label: Option<String>,
    algorithm: Option<Algorithm>,
) -> Result<Selection, u8> {
    let explicit_backend = match backend {
        Some(backend) => Some(parse_backend(&backend)?),
        None => None,
    };
    if let Some(label) = label {
        let backend = match explicit_backend {
            Some(backend) => backend,
            None => parse_backend(cfg.key.backend_or_fallback())?,
        };
        return Ok(Selection { backend, label });
    }
    let algorithm = algorithm.unwrap_or(Algorithm::Ed25519);
    let configured_ref = configured_ref_explicit(cfg, algorithm);
    let key_ref = match configured_ref
        .unwrap_or_else(|| configured_ref_or_fallback(cfg, algorithm))
        .parse::<KeyRef>()
    {
        Ok(key_ref) => key_ref,
        Err(error) => {
            return Err(emit_err(
                &format!("config key ref: {error}"),
                exit::CONFIG_ERROR,
            ));
        }
    };
    let backend = match explicit_backend {
        Some(backend) => backend,
        None if configured_ref.is_some() => key_ref.backend(),
        None => parse_backend(cfg.key.backend_or_fallback())?,
    };
    Ok(Selection {
        backend,
        label: key_ref.label().to_owned(),
    })
}

fn configured_ref_explicit(cfg: &Config, algorithm: Algorithm) -> Option<&str> {
    match algorithm {
        Algorithm::Ed25519 if !cfg.key.ed25519_ref.is_empty() => Some(cfg.key.ed25519_ref.as_str()),
        Algorithm::Secp256k1 if !cfg.key.secp256k1_ref.is_empty() => {
            Some(cfg.key.secp256k1_ref.as_str())
        }
        Algorithm::P256 if !cfg.key.p256_ref.is_empty() => Some(cfg.key.p256_ref.as_str()),
        _ if !cfg.key.default_ref.is_empty() => Some(cfg.key.default_ref.as_str()),
        _ => None,
    }
}

fn configured_ref_or_fallback(cfg: &Config, algorithm: Algorithm) -> &str {
    match algorithm {
        Algorithm::Ed25519 => cfg.key.ed25519_ref_or_fallback(),
        Algorithm::Secp256k1 => cfg.key.secp256k1_ref_or_fallback(),
        Algorithm::P256 => cfg.key.p256_ref_or_fallback(),
        // BLS threshold keystore ref defaults to the generic
        // `key.default_ref` (or the documented `software:default`
        // fallback). The planned release-party CLI will introduce a
        // dedicated `key.bls12381_thr_ref` knob; until then the
        // generic ref is enough.
        #[cfg(feature = "bls-threshold")]
        Algorithm::Bls12381Threshold => cfg.key.default_ref_or_fallback(),
    }
}

fn parse_backend(backend: &str) -> Result<BackendKind, u8> {
    match backend.parse::<BackendKind>() {
        Ok(parsed) => Ok(parsed),
        Err(error) => Err(emit_err(
            &format!("key backend: {error}"),
            exit::CONFIG_ERROR,
        )),
    }
}

fn store_for_backend(backend: BackendKind) -> Result<Box<dyn Keystore>, u8> {
    open_backend(backend)
        .map_err(|error| emit_err(&format!("keystore backend: {error}"), exit::UNAVAILABLE))
}

fn read_config() -> Result<Config, u8> {
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(error) => return Err(emit_err(&format!("cwd: {error}"), exit::NOINPUT)),
    };
    let layout = super::resolve_layout(&cwd)?;
    config::read_or_default(&layout)
        .map_err(|error| emit_err(&format!("config: {error}"), exit::CONFIG_ERROR))
}

fn parse_algorithm(value: &str) -> Result<Algorithm, u8> {
    value
        .parse()
        .map_err(|error| emit_err(&format!("algorithm: {error}"), exit::USAGE))
}

fn optional_algorithm(value: Option<&str>) -> Result<Option<Algorithm>, u8> {
    value.map(parse_algorithm).transpose()
}

fn optional_algorithm_or_default(value: Option<&str>) -> Result<Algorithm, u8> {
    match optional_algorithm(value)? {
        Some(algorithm) => Ok(algorithm),
        None => Ok(Algorithm::Ed25519),
    }
}

#[allow(clippy::fn_params_excessive_bools)]
fn attrs_from_flags(
    extractable: bool,
    non_extractable: bool,
    device_bound: bool,
    require_user_presence: bool,
) -> KeyAttrs {
    let mut attrs = KeyAttrs::default();
    if extractable {
        attrs.extractable = true;
    }
    if non_extractable {
        attrs.extractable = false;
    }
    attrs.device_bound = device_bound;
    attrs.require_user_presence = require_user_presence;
    attrs
}

fn print_metadata(metadata: &mkit_keystore::KeyMetadata) {
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "backend = {}", metadata.backend());
    let _ = writeln!(stdout, "label = {}", metadata.label());
    let _ = writeln!(stdout, "algorithm = {}", metadata.algorithm());
    let _ = writeln!(stdout, "public_key = {}", hex_lower(metadata.public_key()));
    let _ = writeln!(stdout, "keyid = {}", metadata.keyid());
    let _ = writeln!(stdout, "extractable = {}", metadata.extractable);
    let _ = writeln!(
        stdout,
        "require_user_presence = {}",
        metadata.require_user_presence
    );
    let _ = writeln!(stdout, "device_bound = {}", metadata.device_bound);
}

fn print_capabilities(capabilities: &Capabilities) {
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "capabilities.backend = {}", capabilities.backend);
    let _ = writeln!(
        stdout,
        "capabilities.algorithms = {}",
        algorithms_csv(capabilities)
    );
    let _ = writeln!(
        stdout,
        "capabilities.can_generate = {}",
        capabilities.can_generate
    );
    let _ = writeln!(
        stdout,
        "capabilities.can_import = {}",
        capabilities.can_import
    );
    let _ = writeln!(
        stdout,
        "capabilities.can_export = {}",
        capabilities.can_export
    );
    let _ = writeln!(
        stdout,
        "capabilities.can_delete = {}",
        capabilities.can_delete
    );
    let _ = writeln!(
        stdout,
        "capabilities.supports_listing = {}",
        capabilities.supports_listing
    );
    let _ = writeln!(
        stdout,
        "capabilities.supports_user_presence = {}",
        capabilities.supports_user_presence
    );
    let _ = writeln!(
        stdout,
        "capabilities.supports_device_bound = {}",
        capabilities.supports_device_bound
    );
    let _ = writeln!(
        stdout,
        "capabilities.supports_non_extractable = {}",
        capabilities.supports_non_extractable
    );
}

fn algorithms_csv(capabilities: &Capabilities) -> String {
    capabilities
        .algorithms
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn json_capabilities(capabilities: &Capabilities) -> String {
    let algorithms = capabilities
        .algorithms
        .iter()
        .map(|algorithm| format!("\"{algorithm}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"backend\":\"{}\",\"algorithms\":[{}],\"can_generate\":{},\"can_import\":{},\"can_export\":{},\"can_delete\":{},\"supports_listing\":{},\"supports_user_presence\":{},\"supports_device_bound\":{},\"supports_non_extractable\":{}}}",
        capabilities.backend,
        algorithms,
        capabilities.can_generate,
        capabilities.can_import,
        capabilities.can_export,
        capabilities.can_delete,
        capabilities.supports_listing,
        capabilities.supports_user_presence,
        capabilities.supports_device_bound,
        capabilities.supports_non_extractable
    )
}

fn parse_secret_hex(hex: &str) -> Result<[u8; 32], u8> {
    if hex.len() != 64 {
        return Err(emit_err(
            "--hex must be exactly 64 hex characters",
            exit::DATAERR,
        ));
    }
    let mut out = [0u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_value(chunk[0])?;
        let low = hex_value(chunk[1])?;
        out[index] = (high << 4) | low;
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(emit_err("invalid hex character", exit::DATAERR)),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch => out.push(ch),
        }
    }
    out
}

#[allow(clippy::needless_pass_by_value)]
fn keystore_error(error: mkit_keystore::Error) -> u8 {
    emit_err(&format!("keystore: {error}"), exit::DATAERR)
}

use super::error as emit_err;

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<KeyOpts, clap::Error> {
        KeyOpts::try_parse_from(
            std::iter::once("mkit key".to_owned()).chain(args.iter().map(|arg| (*arg).to_owned())),
        )
    }

    #[test]
    fn generate_accepts_equals_options() {
        let opts = parse(&["generate", "--backend=software-raw", "--algorithm=ed25519"]).unwrap();
        let KeyCommand::Generate(generate) = opts.command else {
            panic!("expected generate command");
        };
        assert_eq!(generate.backend.as_deref(), Some("software-raw"));
        assert_eq!(generate.algorithm.as_deref(), Some("ed25519"));
    }

    #[test]
    fn import_accepts_equals_options() {
        let secret = "03".repeat(32);
        let opts = parse(&["import", "--algorithm=ed25519", &format!("--hex={secret}")]).unwrap();
        let KeyCommand::Import(import) = opts.command else {
            panic!("expected import command");
        };
        assert_eq!(import.algorithm.as_deref(), Some("ed25519"));
        assert_eq!(import.hex.as_deref(), Some(secret.as_str()));
    }

    #[test]
    fn extractable_flags_conflict() {
        assert!(parse(&["generate", "--extractable", "--non-extractable"]).is_err());
        assert!(parse(&["import", "--extractable", "--non-extractable"]).is_err());
    }
}
