// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use saml2_sp::{create_self_signed_key_pair, metadata_document, read_idp_metadata, resolve_config};
use serde_json::{Map, Value};

const USAGE: &str = "Usage:
  saml2-sp generate-keys --config <saml.json> [--cn <name>] [--days <n>] [--bits <n>] [--force]
  saml2-sp generate-keys --key <file> --cert <file> [--cn <name>] [--days <n>] [--bits <n>] [--force]
      A new RSA key and a self-signed certificate, written where the configuration's privateKey and
      certificate point (or to --key and --cert). Refuses to replace existing files without --force.
      The common name defaults to the host of the configuration's entityId.

  saml2-sp metadata --config <saml.json> [--out <file>] [--entity-id <url>] [--acs-url <url>]
      This service provider's SAML metadata, from the configuration and its certificate. Written to
      --out, or to standard output. --entity-id and --acs-url replace the file's values for this run.

  saml2-sp summarize-idp
      Read identity-provider metadata on standard input. Write its entityID, its SSO URL, and one
      artifact-resolution URL per line.";

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run(argv: Vec<String>) -> Result<(), String> {
    let (command, args) = parse_args(&argv)?;
    if command.is_empty() || args.get("help").map(String::as_str) == Some("true") || command == "help" {
        println!("{USAGE}");
        return Ok(());
    }
    match command.as_str() {
        "generate-keys" => generate_keys(&args),
        "metadata" => write_metadata(&args),
        "summarize-idp" => summarize(),
        other => Err(format!("unknown command {other}\n\n{USAGE}")),
    }
}

fn parse_args(argv: &[String]) -> Result<(String, BTreeMap<String, String>), String> {
    let (command, rest) = if argv.is_empty() { (String::new(), &[][..]) } else { (argv[0].clone(), &argv[1..]) };
    let mut args = BTreeMap::new();
    let mut index = 0;
    while index < rest.len() {
        let item = &rest[index];
        if !item.starts_with("--") {
            return Err(format!("unexpected argument {item}\n\n{USAGE}"));
        }
        let key = &item[2..];
        if key == "force" || key == "help" {
            args.insert(key.to_string(), "true".to_string());
            index += 1;
            continue;
        }
        if index + 1 >= rest.len() || rest[index + 1].starts_with("--") {
            return Err(format!("--{key} needs a value\n\n{USAGE}"));
        }
        args.insert(key.to_string(), rest[index + 1].clone());
        index += 2;
    }
    Ok((command, args))
}

struct Locations { key: String, cert: String, cn: String }

fn generate_keys(args: &BTreeMap<String, String>) -> Result<(), String> {
    let paths = key_paths(args)?;
    if args.get("force").map(String::as_str) != Some("true") && (exists(&paths.key) || exists(&paths.cert)) {
        let which = if exists(&paths.key) { &paths.key } else { &paths.cert };
        return Err(format!("{which} already exists; pass --force to replace the key pair.\nReplacing it means giving the identity provider the new metadata before the next sign-in."));
    }
    let days = match args.get("days").map(String::as_str) {
        Some(raw) if !raw.is_empty() => raw.parse::<i64>().ok().filter(|n| *n > 0).ok_or_else(|| "--days must be a positive whole number".to_string())?,
        _ => 1095,
    };
    let bits = match args.get("bits").map(String::as_str) {
        Some(raw) if !raw.is_empty() => {
            let n = raw.parse::<usize>().unwrap_or(0);
            if n != 2048 && n != 3072 && n != 4096 { return Err("--bits must be 2048, 3072 or 4096".to_string()); }
            n
        }
        _ => 3072,
    };
    let pair = create_self_signed_key_pair(&paths.cn, days, bits).map_err(|e| e.to_string())?;
    write_mode(&paths.key, &pair.private_key_pem, 0o600)?;
    write_mode(&paths.cert, &pair.certificate_pem, 0o644)?;
    println!("Wrote the private key  {} (mode 600)", paths.key);
    println!("Wrote the certificate  {}", paths.cert);
    println!("  subject   CN={}", paths.cn);
    println!("  valid to  {}", pair.valid_to());
    println!("  sha256    {}", pair.fingerprint256());
    Ok(())
}

fn key_paths(args: &BTreeMap<String, String>) -> Result<Locations, String> {
    let mut key = args.get("key").cloned().unwrap_or_default();
    let mut cert = args.get("cert").cloned().unwrap_or_default();
    let mut cn = args.get("cn").cloned().unwrap_or_default();
    if let Some(config_path) = args.get("config") {
        let raw = read_object(config_path)?;
        let base = abs_path(config_path).parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
        let at = |value: &str, what: &str| -> Result<String, String> {
            if value.is_empty() || value.contains("-----BEGIN ") || value.starts_with("env:") {
                return Err(format!("{config_path}'s {what} must be a file path for generate-keys to write to"));
            }
            let text = value.strip_prefix("file:").unwrap_or(value);
            let path = if Path::new(text).is_absolute() { PathBuf::from(text) } else { base.join(text) };
            Ok(abs_path(path.to_string_lossy().as_ref()).to_string_lossy().to_string())
        };
        if key.is_empty() { key = at(&raw_string(&raw, "privateKey"), "privateKey")?; }
        if cert.is_empty() { cert = at(&raw_string(&raw, "certificate"), "certificate")?; }
        if cn.is_empty() {
            let entity = raw_string(&raw, "entityId");
            if !entity.is_empty() { cn = host_of(&entity).unwrap_or(entity); }
        }
    }
    if key.is_empty() || cert.is_empty() {
        return Err(format!("generate-keys needs --config, or --key and --cert\n\n{USAGE}"));
    }
    if cn.is_empty() { cn = "saml2-sp service provider".to_string(); }
    Ok(Locations { key: abs_string(&key), cert: abs_string(&cert), cn })
}

fn write_metadata(args: &BTreeMap<String, String>) -> Result<(), String> {
    let config_path = args.get("config").map(String::as_str).unwrap_or("");
    if config_path.is_empty() { return Err(format!("metadata needs --config\n\n{USAGE}")); }
    let mut raw = read_object(config_path)?;
    raw.remove("idpCa");
    if let Some(entity) = args.get("entity-id").filter(|v| !v.is_empty()) { raw.insert("entityId".into(), Value::String(entity.clone())); }
    if let Some(acs) = args.get("acs-url").filter(|v| !v.is_empty()) { raw.insert("acsUrl".into(), Value::String(acs.clone())); }
    let base = abs_path(config_path).parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
    let cfg = resolve_config(&raw, &base).map_err(|e| e.to_string())?;
    let xml = metadata_document(&cfg);
    if let Some(target) = args.get("out").filter(|v| !v.is_empty()) {
        let target = abs_string(target);
        write_mode(&target, &xml, 0o644)?;
        println!("Wrote the service provider metadata to {target}");
        return Ok(());
    }
    print!("{xml}");
    let _ = std::io::stdout().flush();
    Ok(())
}

fn summarize() -> Result<(), String> {
    let mut raw = Vec::new();
    std::io::stdin().take(2 * 1024 * 1024).read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&raw);
    let meta = read_idp_metadata(&text).map_err(|e| e.to_string())?;
    println!("{}", meta.entity_id);
    let sso = meta.sso.get("redirect").cloned().filter(|v| !v.is_empty()).or_else(|| meta.sso.get("post").cloned()).unwrap_or_default();
    println!("{sso}");
    let mut indexes: Vec<i32> = meta.artifact_resolution_services.keys().copied().collect();
    indexes.sort_unstable();
    for index in indexes {
        if let Some(url) = meta.artifact_resolution_services.get(&index) { println!("{url}"); }
    }
    Ok(())
}

fn read_object(path: &str) -> Result<Map<String, Value>, String> {
    let raw = std::fs::read(path).map_err(|e| e.to_string())?;
    let parsed: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    parsed.as_object().cloned().ok_or_else(|| format!("{path} is not a JSON object"))
}

fn raw_string(obj: &Map<String, Value>, key: &str) -> String {
    obj.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

fn host_of(entity: &str) -> Option<String> {
    let rest = entity.split_once("://").map(|(_, rest)| rest).unwrap_or(entity);
    let hostport = rest.split(['/', '?', '#']).next().unwrap_or("");
    if hostport.is_empty() { return None; }
    let host = if let Some(inner) = hostport.strip_prefix('[') { inner.split(']').next().unwrap_or("") } else { hostport.split(':').next().unwrap_or("") };
    if host.is_empty() { None } else { Some(host.to_string()) }
}

fn exists(path: &str) -> bool { Path::new(path).exists() }

fn abs_path(path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() { path } else { std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join(path) }
}

fn abs_string(path: &str) -> String { abs_path(path).to_string_lossy().to_string() }

fn write_mode(path: &str, text: &str, mode: u32) -> Result<(), String> {
    if let Some(dir) = Path::new(path).parent() {
        if !dir.as_os_str().is_empty() { std::fs::create_dir_all(dir).map_err(|e| e.to_string())?; }
    }
    std::fs::write(path, text).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())?;
    }
    let _ = mode;
    Ok(())
}
