//! `mkit key` keystore management commands.

use std::io::Write as _;
use std::path::Path;

use mkit_keystore::{
    Algorithm, BackendKind, GenerateOptions, ImportOptions, KeyAttrs, KeyRef, KeySelector,
    Keystore, SecretKey, SoftwareKeystore,
};
use zeroize::Zeroize;

use crate::config::{self, Config};
use crate::exit;

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let Some((subcommand, rest)) = args.split_first() else {
        return usage();
    };
    match subcommand.as_str() {
        "generate" => generate(rest),
        "list" => list(rest),
        "import" => import(rest),
        "export" => export(rest),
        "delete" => delete(rest),
        "-h" | "--help" | "help" => usage_ok(),
        other => emit_err(&format!("unknown key subcommand `{other}`"), exit::USAGE),
    }
}

fn generate(args: &[String]) -> u8 {
    let cfg = match read_config() {
        Ok(cfg) => cfg,
        Err(code) => return code,
    };
    let mut backend = None;
    let mut label = None;
    let mut algorithm = Algorithm::Ed25519;
    let mut attrs = KeyAttrs::default();
    let mut force = false;
    let mut print_pubkey = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--backend" => match take_value(args, &mut i, "--backend") {
                Ok(value) => backend = Some(value),
                Err(code) => return code,
            },
            "--label" => match take_value(args, &mut i, "--label") {
                Ok(value) => label = Some(value),
                Err(code) => return code,
            },
            "--algorithm" => match take_value(args, &mut i, "--algorithm") {
                Ok(value) => match parse_algorithm(&value) {
                    Ok(value) => algorithm = value,
                    Err(code) => return code,
                },
                Err(code) => return code,
            },
            "--extractable" => attrs.extractable = true,
            "--non-extractable" => attrs.extractable = false,
            "--device-bound" => attrs.device_bound = true,
            "--require-user-presence" => attrs.require_user_presence = true,
            "--force" => force = true,
            "--print-pubkey" => print_pubkey = true,
            other => return emit_err(&format!("unknown option `{other}`"), exit::USAGE),
        }
        i += 1;
    }
    let selection = match selection_for(&cfg, backend, label, Some(algorithm)) {
        Ok(selection) => selection,
        Err(code) => return code,
    };
    let store = match store_for_backend(&selection.backend) {
        Ok(store) => store,
        Err(code) => return code,
    };
    let signer = match store.generate(
        &selection.label,
        algorithm,
        attrs,
        GenerateOptions { overwrite: force },
    ) {
        Ok(signer) => signer,
        Err(error) => return keystore_error(error),
    };
    let metadata = match signer.metadata() {
        Ok(metadata) => metadata,
        Err(error) => return keystore_error(error),
    };
    print_metadata(&metadata);
    if print_pubkey {
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{}", metadata.keyid);
    }
    exit::OK
}

fn list(args: &[String]) -> u8 {
    let cfg = match read_config() {
        Ok(cfg) => cfg,
        Err(code) => return code,
    };
    let mut backend = None;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--backend" => match take_value(args, &mut i, "--backend") {
                Ok(value) => backend = Some(value),
                Err(code) => return code,
            },
            "--json" => json = true,
            other => return emit_err(&format!("unknown option `{other}`"), exit::USAGE),
        }
        i += 1;
    }
    let backend = backend.unwrap_or_else(|| cfg.key.backend_or_fallback().to_owned());
    let store = match store_for_backend(&backend) {
        Ok(store) => store,
        Err(code) => return code,
    };
    let mut keys = match store.list() {
        Ok(keys) => keys,
        Err(error) => return keystore_error(error),
    };
    keys.sort_by(|left, right| {
        (&left.backend, &left.label, left.algorithm).cmp(&(
            &right.backend,
            &right.label,
            right.algorithm,
        ))
    });
    let mut stdout = std::io::stdout().lock();
    if json {
        let _ = write!(stdout, "[");
        for (index, key) in keys.iter().enumerate() {
            if index > 0 {
                let _ = write!(stdout, ",");
            }
            let _ = write!(
                stdout,
                "{{\"backend\":\"{}\",\"label\":\"{}\",\"algorithm\":\"{}\",\"keyid\":\"{}\",\"extractable\":{},\"require_user_presence\":{},\"device_bound\":{}}}",
                key.backend,
                json_escape(&key.label),
                key.algorithm,
                json_escape(&key.keyid),
                key.extractable,
                key.require_user_presence,
                key.device_bound
            );
        }
        let _ = writeln!(stdout, "]");
    } else {
        for key in keys {
            let _ = writeln!(
                stdout,
                "{} {} {} {} extractable={} user_presence={} device_bound={}",
                key.backend,
                key.label,
                key.algorithm,
                key.keyid,
                key.extractable,
                key.require_user_presence,
                key.device_bound
            );
        }
    }
    exit::OK
}

fn import(args: &[String]) -> u8 {
    let cfg = match read_config() {
        Ok(cfg) => cfg,
        Err(code) => return code,
    };
    let mut backend = None;
    let mut label = None;
    let mut algorithm = None;
    let mut hex = None;
    let mut file = None;
    let mut attrs = KeyAttrs::default();
    let mut force = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--backend" => match take_value(args, &mut i, "--backend") {
                Ok(value) => backend = Some(value),
                Err(code) => return code,
            },
            "--label" => match take_value(args, &mut i, "--label") {
                Ok(value) => label = Some(value),
                Err(code) => return code,
            },
            "--algorithm" => match take_value(args, &mut i, "--algorithm") {
                Ok(value) => match parse_algorithm(&value) {
                    Ok(value) => algorithm = Some(value),
                    Err(code) => return code,
                },
                Err(code) => return code,
            },
            "--hex" => match take_value(args, &mut i, "--hex") {
                Ok(value) => hex = Some(value),
                Err(code) => return code,
            },
            "--file" => match take_value(args, &mut i, "--file") {
                Ok(value) => file = Some(value),
                Err(code) => return code,
            },
            "--extractable" => attrs.extractable = true,
            "--non-extractable" => attrs.extractable = false,
            "--device-bound" => attrs.device_bound = true,
            "--require-user-presence" => attrs.require_user_presence = true,
            "--force" => force = true,
            other => return emit_err(&format!("unknown option `{other}`"), exit::USAGE),
        }
        i += 1;
    }
    let Some(algorithm) = algorithm else {
        return emit_err("mkit key import requires --algorithm", exit::USAGE);
    };
    if hex.is_some() == file.is_some() {
        return emit_err(
            "mkit key import requires exactly one of --hex or --file",
            exit::USAGE,
        );
    }
    let selection = match selection_for(&cfg, backend, label, Some(algorithm)) {
        Ok(selection) => selection,
        Err(code) => return code,
    };
    let mut secret = match (hex, file) {
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
    let store = match store_for_backend(&selection.backend) {
        Ok(store) => store,
        Err(code) => return code,
    };
    let signer = match store.import(
        &selection.label,
        wrapped,
        attrs,
        ImportOptions { overwrite: force },
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

fn export(args: &[String]) -> u8 {
    let cfg = match read_config() {
        Ok(cfg) => cfg,
        Err(code) => return code,
    };
    let mut backend = None;
    let mut label = None;
    let mut algorithm = None;
    let mut unsafe_print_secret = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--backend" => match take_value(args, &mut i, "--backend") {
                Ok(value) => backend = Some(value),
                Err(code) => return code,
            },
            "--label" => match take_value(args, &mut i, "--label") {
                Ok(value) => label = Some(value),
                Err(code) => return code,
            },
            "--algorithm" => match take_value(args, &mut i, "--algorithm") {
                Ok(value) => match parse_algorithm(&value) {
                    Ok(value) => algorithm = Some(value),
                    Err(code) => return code,
                },
                Err(code) => return code,
            },
            "--unsafe-print-secret" => unsafe_print_secret = true,
            other => return emit_err(&format!("unknown option `{other}`"), exit::USAGE),
        }
        i += 1;
    }
    if !unsafe_print_secret {
        return emit_err(
            "mkit key export requires --unsafe-print-secret",
            exit::USAGE,
        );
    }
    let selection = match selection_for(&cfg, backend, label, algorithm) {
        Ok(selection) => selection,
        Err(code) => return code,
    };
    let store = match store_for_backend(&selection.backend) {
        Ok(store) => store,
        Err(code) => return code,
    };
    let selector = KeySelector {
        label: selection.label,
        algorithm,
    };
    let secret = match store.export(&selector) {
        Ok(secret) => secret,
        Err(error) => return keystore_error(error),
    };
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "warning: printing secret key material to stdout");
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{}", hex_lower(secret.expose_secret()));
    exit::OK
}

fn delete(args: &[String]) -> u8 {
    let cfg = match read_config() {
        Ok(cfg) => cfg,
        Err(code) => return code,
    };
    let mut backend = None;
    let mut label = None;
    let mut algorithm = None;
    let mut yes = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--backend" => match take_value(args, &mut i, "--backend") {
                Ok(value) => backend = Some(value),
                Err(code) => return code,
            },
            "--label" => match take_value(args, &mut i, "--label") {
                Ok(value) => label = Some(value),
                Err(code) => return code,
            },
            "--algorithm" => match take_value(args, &mut i, "--algorithm") {
                Ok(value) => match parse_algorithm(&value) {
                    Ok(value) => algorithm = Some(value),
                    Err(code) => return code,
                },
                Err(code) => return code,
            },
            "--yes" => yes = true,
            other => return emit_err(&format!("unknown option `{other}`"), exit::USAGE),
        }
        i += 1;
    }
    if !yes {
        return emit_err("mkit key delete requires --yes", exit::USAGE);
    }
    let selection = match selection_for(&cfg, backend, label, algorithm) {
        Ok(selection) => selection,
        Err(code) => return code,
    };
    let store = match store_for_backend(&selection.backend) {
        Ok(store) => store,
        Err(code) => return code,
    };
    let selector = KeySelector {
        label: selection.label.clone(),
        algorithm,
    };
    match store.delete(&selector) {
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
    backend: String,
    label: String,
}

fn selection_for(
    cfg: &Config,
    backend: Option<String>,
    label: Option<String>,
    algorithm: Option<Algorithm>,
) -> Result<Selection, u8> {
    let backend = backend.unwrap_or_else(|| cfg.key.backend_or_fallback().to_owned());
    if let Some(label) = label {
        return Ok(Selection { backend, label });
    }
    let key_ref =
        match configured_ref(cfg, algorithm.unwrap_or(Algorithm::Ed25519)).parse::<KeyRef>() {
            Ok(key_ref) => key_ref,
            Err(error) => {
                return Err(emit_err(
                    &format!("config key ref: {error}"),
                    exit::CONFIG_ERROR,
                ));
            }
        };
    Ok(Selection {
        backend,
        label: key_ref.label,
    })
}

fn configured_ref(cfg: &Config, algorithm: Algorithm) -> &str {
    match algorithm {
        Algorithm::Ed25519 => cfg.key.ed25519_ref_or_fallback(),
        Algorithm::Secp256k1 => cfg.key.secp256k1_ref_or_fallback(),
        Algorithm::P256 => cfg.key.p256_ref_or_fallback(),
    }
}

fn store_for_backend(backend: &str) -> Result<SoftwareKeystore, u8> {
    let parsed = match backend.parse::<BackendKind>() {
        Ok(parsed) => parsed,
        Err(error) => {
            return Err(emit_err(
                &format!("key backend: {error}"),
                exit::CONFIG_ERROR,
            ));
        }
    };
    match parsed {
        BackendKind::Software => SoftwareKeystore::new()
            .map_err(|error| emit_err(&format!("software keystore: {error}"), exit::UNAVAILABLE)),
        other => Err(emit_err(
            &format!("key backend `{other}` is not supported in Foundation V1"),
            exit::UNAVAILABLE,
        )),
    }
}

fn read_config() -> Result<Config, u8> {
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(error) => return Err(emit_err(&format!("cwd: {error}"), exit::NOINPUT)),
    };
    config::read_or_default(&cwd)
        .map_err(|error| emit_err(&format!("config: {error}"), exit::CONFIG_ERROR))
}

fn parse_algorithm(value: &str) -> Result<Algorithm, u8> {
    value
        .parse()
        .map_err(|error| emit_err(&format!("algorithm: {error}"), exit::USAGE))
}

fn take_value(args: &[String], index: &mut usize, option: &str) -> Result<String, u8> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| emit_err(&format!("{option} requires a value"), exit::USAGE))
}

fn print_metadata(metadata: &mkit_keystore::KeyMetadata) {
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "backend = {}", metadata.backend);
    let _ = writeln!(stdout, "label = {}", metadata.label);
    let _ = writeln!(stdout, "algorithm = {}", metadata.algorithm);
    let _ = writeln!(stdout, "public_key = {}", hex_lower(&metadata.public_key));
    let _ = writeln!(stdout, "keyid = {}", metadata.keyid);
    let _ = writeln!(stdout, "extractable = {}", metadata.extractable);
    let _ = writeln!(
        stdout,
        "require_user_presence = {}",
        metadata.require_user_presence
    );
    let _ = writeln!(stdout, "device_bound = {}", metadata.device_bound);
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

fn usage() -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(USAGE.as_bytes());
    exit::USAGE
}

fn usage_ok() -> u8 {
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(USAGE.as_bytes());
    exit::OK
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}

const USAGE: &str = "\
usage: mkit key <subcommand> [args]

subcommands:
  generate [--backend software] [--label <label>] [--algorithm ed25519|secp256k1|p256]
           [--extractable|--non-extractable] [--device-bound]
           [--require-user-presence] [--force] [--print-pubkey]
  list [--backend software] [--json]
  import --algorithm ed25519|secp256k1|p256 [--backend software] [--label <label>]
         (--hex <64-hex> | --file <path>) [--extractable|--non-extractable]
         [--device-bound] [--require-user-presence] [--force]
  export [--backend software] [--label <label>] [--algorithm ed25519|secp256k1|p256]
         --unsafe-print-secret
  delete [--backend software] [--label <label>] [--algorithm ed25519|secp256k1|p256] --yes
";
