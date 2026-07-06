use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, LauncherError>;
const DEFAULT_RDP_PROFILE: &str = "mac";
const TEMPLATE_RDP_FILE_NAME: &str = "mstsc-success-template.rdp";

#[derive(Debug)]
enum LauncherError {
    Message(String),
    Io(io::Error),
}

impl fmt::Display for LauncherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LauncherError::Message(message) => write!(f, "{message}"),
            LauncherError::Io(err) => write!(f, "{err}"),
        }
    }
}

impl From<io::Error> for LauncherError {
    fn from(value: io::Error) -> Self {
        LauncherError::Io(value)
    }
}

#[derive(Debug, Default)]
struct Cli {
    input: Option<String>,
    inspect: bool,
    write_only: bool,
    register: bool,
    unregister: bool,
    mstsc: Option<PathBuf>,
    profile: Option<String>,
    log: Option<PathBuf>,
    rdp_file: Option<PathBuf>,
    set_template: Option<PathBuf>,
    clear_template: bool,
    no_wait: bool,
    direct_mstsc: bool,
    use_cmdkey: bool,
    monitor_seconds: u64,
    help: bool,
}

#[derive(Debug)]
struct RdpLaunch {
    protocol: String,
    name: String,
    content: String,
    /// JumpServer connection-token secret (`token.value`). The razor RDP gateway
    /// authenticates the native RDP login with username `user|token_id` and this
    /// value as the password; it is never written into the `.rdp` file.
    password: Option<String>,
    inner_config_base64: bool,
    config_strategy: &'static str,
    compat_patches: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

fn main() {
    let cli = match parse_cli(env::args().skip(1).collect()) {
        Ok(cli) => cli,
        Err(err) => {
            eprintln!("Error: {err}");
            print_help();
            std::process::exit(2);
        }
    };

    if cli.help {
        print_help();
        return;
    }

    let log_path = cli.log.clone().unwrap_or_else(default_log_path);
    if let Err(err) = run(cli, &log_path) {
        let _ = append_log(&log_path, &format!("ERROR: {err}"));
        eprintln!("Error: {err}");
        std::process::exit(1);
    }
}

fn run(cli: Cli, log_path: &Path) -> Result<()> {
    append_log(log_path, "starting jms-rdp-launcher")?;

    if cli.register {
        register_protocol(
            log_path,
            cli.profile.as_deref(),
            cli.direct_mstsc,
            cli.use_cmdkey,
        )?;
        return Ok(());
    }

    if cli.unregister {
        unregister_protocol(log_path)?;
        return Ok(());
    }

    if let Some(template_path) = cli.set_template {
        install_template_rdp(&template_path, log_path)?;
        return Ok(());
    }

    if cli.clear_template {
        clear_template_rdp(log_path)?;
        return Ok(());
    }

    if let Some(rdp_file) = cli.rdp_file {
        append_log(
            log_path,
            &format!("launching existing rdp file: {}", rdp_file.display()),
        )?;
        let rdp_content = read_text_file_lossy(&rdp_file).ok();
        return launch_rdp(
            &rdp_file,
            rdp_content.as_deref(),
            None,
            cli.mstsc.as_deref(),
            cli.no_wait,
            cli.direct_mstsc,
            cli.use_cmdkey,
            cli.monitor_seconds,
            log_path,
        );
    }

    let input = cli
        .input
        .ok_or_else(|| LauncherError::Message("missing jms:// input".to_string()))?;
    append_log(
        log_path,
        &format!("raw argument: {}", redact_long(&input, 300)),
    )?;

    let profile = cli.profile.as_deref().unwrap_or(DEFAULT_RDP_PROFILE);
    let launch = parse_jms_link(&input, profile)?;
    append_log(
        log_path,
        &format!(
            "decoded payload: protocol={}, name={}, rdp_bytes={}",
            launch.protocol,
            launch.name,
            launch.content.len()
        ),
    )?;
    append_log(
        log_path,
        &format!(
            "rdp content: inner_config_base64={}, config_strategy={}, compat_patches={}, preview={}",
            launch.inner_config_base64,
            launch.config_strategy,
            if launch.compat_patches.is_empty() {
                "none".to_string()
            } else {
                launch.compat_patches.join(", ")
            },
            rdp_preview(&launch.content)
        ),
    )?;
    append_multiline_log(
        log_path,
        "rdp file content redacted",
        &redact_rdp_content(&launch.content),
    )?;
    append_log(
        log_path,
        &format!(
            "token secret: {}",
            if launch.password.is_some() {
                "present (payload token.value) -> used as RDP password"
            } else {
                "absent (payload has no token.value); JumpServer gateway will reject the login"
            }
        ),
    )?;

    if launch.protocol != "rdp" {
        return Err(LauncherError::Message(format!(
            "unsupported protocol '{}'; this launcher only handles rdp",
            launch.protocol
        )));
    }

    if cli.inspect {
        println!("protocol: {}", launch.protocol);
        println!("name: {}", launch.name);
        println!("inner_config_base64: {}", launch.inner_config_base64);
        println!("config_strategy: {}", launch.config_strategy);
        println!(
            "compat_patches: {}",
            if launch.compat_patches.is_empty() {
                "none".to_string()
            } else {
                launch.compat_patches.join(", ")
            }
        );
        println!("rdp bytes: {}", launch.content.len());
        println!("rdp preview:");
        for line in launch.content.lines().take(20) {
            println!("{line}");
        }
        return Ok(());
    }

    let rdp_path = write_rdp_file(&launch.name, &launch.content)?;
    append_log(log_path, &format!("wrote rdp file: {}", rdp_path.display()))?;
    println!("RDP file: {}", rdp_path.display());

    if cli.write_only {
        return Ok(());
    }

    launch_rdp(
        &rdp_path,
        Some(&launch.content),
        launch.password.as_deref(),
        cli.mstsc.as_deref(),
        cli.no_wait,
        cli.direct_mstsc,
        cli.use_cmdkey,
        cli.monitor_seconds,
        log_path,
    )
}

fn parse_cli(args: Vec<String>) -> Result<Cli> {
    let mut cli = Cli {
        monitor_seconds: 30,
        use_cmdkey: true,
        ..Cli::default()
    };
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "-h" | "--help" => cli.help = true,
            "--inspect" => cli.inspect = true,
            "--write-only" => cli.write_only = true,
            "--register" => cli.register = true,
            "--unregister" => cli.unregister = true,
            "--no-wait" => cli.no_wait = true,
            "--direct-mstsc" => cli.direct_mstsc = true,
            "--use-cmdkey" => cli.use_cmdkey = true,
            "--no-cmdkey" => cli.use_cmdkey = false,
            "--clear-template" => cli.clear_template = true,
            "--monitor-seconds" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| {
                    LauncherError::Message("--monitor-seconds requires a number".to_string())
                })?;
                cli.monitor_seconds = value.parse::<u64>().map_err(|_| {
                    LauncherError::Message(format!("invalid --monitor-seconds value: {value}"))
                })?;
            }
            "--mstsc" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| LauncherError::Message("--mstsc requires a path".to_string()))?;
                cli.mstsc = Some(PathBuf::from(value));
            }
            "--set-template" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| {
                    LauncherError::Message("--set-template requires a .rdp path".to_string())
                })?;
                cli.set_template = Some(PathBuf::from(value));
            }
            "--profile" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| {
                    LauncherError::Message(
                        "--profile requires mac, gnome, template, swift, legacy, or raw"
                            .to_string(),
                    )
                })?;
                let normalized = value.to_ascii_lowercase();
                match normalized.as_str() {
                    "mac" | "gnome" | "template" | "legacy" | "swift" | "raw" => {
                        cli.profile = Some(normalized)
                    }
                    _ => {
                        return Err(LauncherError::Message(format!(
                            "invalid --profile value: {value}; expected mac, gnome, template, swift, legacy, or raw"
                        )))
                    }
                }
            }
            "--log" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| LauncherError::Message("--log requires a path".to_string()))?;
                cli.log = Some(PathBuf::from(value));
            }
            "--rdp-file" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| {
                    LauncherError::Message("--rdp-file requires a path".to_string())
                })?;
                cli.rdp_file = Some(PathBuf::from(value));
            }
            _ if arg.starts_with('-') => {
                return Err(LauncherError::Message(format!("unknown option: {arg}")));
            }
            _ => {
                if cli.input.is_some() {
                    return Err(LauncherError::Message(format!(
                        "unexpected extra argument: {arg}"
                    )));
                }
                cli.input = Some(arg.clone());
            }
        }
        index += 1;
    }
    Ok(cli)
}

fn print_help() {
    println!(
        "jms-rdp-launcher\n\
         \n\
         Usage:\n\
           jms-rdp-launcher.exe [options] \"jms://...\"\n\
           jms-rdp-launcher.exe --register\n\
           jms-rdp-launcher.exe --rdp-file path\\to\\file.rdp\n\
         \n\
         Options:\n\
           --inspect            Decode and print a preview; do not launch mstsc\n\
           --write-only         Decode and write the .rdp file; do not launch mstsc\n\
           --mstsc <path>       Override mstsc.exe path\n\
           --set-template <rdp> Import an MSTSC .rdp file that can connect to Ubuntu directly\n\
           --clear-template     Remove the saved MSTSC template\n\
           --profile <name>     RDP profile: mac, gnome, template, swift, legacy, raw (default mac)\n\
           --log <path>         Override log path\n\
           --rdp-file <path>    Launch an existing .rdp file\n\
           --no-wait            Spawn mstsc and return immediately\n\
           --direct-mstsc       Launch mstsc.exe directly instead of ShellExecute-opening .rdp\n\
           --use-cmdkey         Write username|token_id + token.value to Credential Manager (default)\n\
           --no-cmdkey          Do not write temporary Windows credentials\n\
           --monitor-seconds N  After mstsc returns, wait N seconds and query RDP events (default 30)\n\
           --register           Register this exe as the jms:// handler for current user\n\
           --unregister         Remove the current-user jms:// registration\n"
    );
}

fn parse_jms_link(input: &str, profile: &str) -> Result<RdpLaunch> {
    let trimmed = input.trim().trim_matches('"').trim_matches('\'');
    let payload = trimmed
        .strip_prefix("jms://")
        .or_else(|| trimmed.strip_prefix("JMS://"))
        .unwrap_or(trimmed);
    let payload = percent_decode(payload)?.replace(' ', "+");
    let decoded = base64_decode_lossy_tail(&payload)?;
    let json_text = String::from_utf8(decoded)
        .map_err(|err| LauncherError::Message(format!("decoded payload is not UTF-8: {err}")))?;
    let json = JsonParser::new(&json_text).parse()?;
    extract_rdp_launch(&json, profile)
}

fn extract_rdp_launch(json: &JsonValue, profile: &str) -> Result<RdpLaunch> {
    let object = match json {
        JsonValue::Object(object) => object,
        _ => {
            return Err(LauncherError::Message(
                "decoded payload is not a JSON object".to_string(),
            ))
        }
    };

    let protocol = get_string(object, "protocol")
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let file = match object.get("file") {
        Some(JsonValue::Object(file)) => Some(file),
        _ => None,
    };

    let name = file
        .and_then(|file| get_string(file, "name"))
        .or_else(|| get_string(object, "filename"))
        .or_else(|| get_string(object, "name"))
        .unwrap_or("jumpserver-rdp")
        .to_string();

    let raw_content = file
        .and_then(|file| get_string(file, "content"))
        .or_else(|| get_string(object, "content"))
        .or_else(|| get_string(object, "config"))
        .ok_or_else(|| {
            LauncherError::Message(
                "payload has no file.content/content/config RDP data".to_string(),
            )
        })?
        .to_string();
    let (content, inner_config_base64) = decode_embedded_rdp_config(&raw_content)?;
    let (content, config_strategy, compat_patches) =
        normalize_jumpserver_rdp_config(content, profile);
    let password = extract_token_secret(object);

    Ok(RdpLaunch {
        protocol,
        name,
        content,
        password,
        inner_config_base64,
        config_strategy,
        compat_patches,
    })
}

/// Pull the JumpServer connection-token secret out of the decoded payload.
///
/// Newer JumpServer emits `"token": {"id": "...", "value": "<secret>"}` (and a
/// mirror top-level `"value"`); some builds put the secret directly in a
/// `"token": "<secret>"` string. The token *id* travels in the RDP username
/// (`user|token_id`) and is only a lookup key, so it is never treated as the
/// secret here.
fn extract_token_secret(object: &BTreeMap<String, JsonValue>) -> Option<String> {
    if let Some(JsonValue::Object(token)) = object.get("token") {
        if let Some(value) = get_string(token, "value") {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    if let Some(JsonValue::String(token)) = object.get("token") {
        if !token.is_empty() {
            return Some(token.clone());
        }
    }
    if let Some(value) = get_string(object, "value") {
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

fn normalize_jumpserver_rdp_config(
    content: String,
    profile: &str,
) -> (String, &'static str, Vec<String>) {
    if has_jumpserver_token_username(&content) {
        match profile {
            "raw" => return (content, "raw_jumpserver", Vec::new()),
            "template" => {
                if let Some(regenerated) = build_template_based_mstsc_rdp_config(&content) {
                    return (regenerated, "mstsc_saved_template", Vec::new());
                }
                if let Some(regenerated) = build_mac_microsoft_remote_desktop_rdp_config(&content) {
                    return (
                        regenerated,
                        "mac_microsoft_remote_desktop_compatible",
                        vec!["template_not_installed".to_string()],
                    );
                }
            }
            "mac" => {
                if let Some(regenerated) = build_mac_microsoft_remote_desktop_rdp_config(&content) {
                    return (
                        regenerated,
                        "mac_microsoft_remote_desktop_compatible",
                        Vec::new(),
                    );
                }
            }
            "gnome" => {
                if let Some(regenerated) = build_gnome_mstsc_rdp_config(&content) {
                    return (regenerated, "mstsc_gnome_compatible", Vec::new());
                }
            }
            "swift" => {
                if let Some(regenerated) = build_swift_compatible_mstsc_rdp_config(&content) {
                    return (regenerated, "swift_compatible_mstsc", Vec::new());
                }
            }
            "legacy" => {
                if let Some(regenerated) = build_mstsc_legacy_graphics_rdp_config(&content) {
                    return (regenerated, "mstsc_legacy_graphics", Vec::new());
                }
            }
            _ => {}
        }
    }

    (content, "raw", Vec::new())
}

fn build_gnome_mstsc_rdp_config(content: &str) -> Option<String> {
    let full_address = rdp_setting_value(content, "full address")?;
    let username = rdp_setting_value(content, "username")?;

    if full_address.trim().is_empty() || username.trim().is_empty() {
        return None;
    }

    let overrides = [
        (
            "full address",
            format!("full address:s:{}", full_address.trim()),
        ),
        ("username", format!("username:s:{}", username.trim())),
        ("desktopwidth", "desktopwidth:i:1920".to_string()),
        ("desktopheight", "desktopheight:i:1080".to_string()),
        ("screen mode id", "screen mode id:i:1".to_string()),
        ("session bpp", "session bpp:i:32".to_string()),
        ("compression", "compression:i:1".to_string()),
        ("networkautodetect", "networkautodetect:i:1".to_string()),
        ("bandwidthautodetect", "bandwidthautodetect:i:1".to_string()),
        ("smart sizing", "smart sizing:i:1".to_string()),
        ("dynamic resolution", "dynamic resolution:i:1".to_string()),
        ("use multimon", "use multimon:i:0".to_string()),
        ("use multitransport", "use multitransport:i:0".to_string()),
        ("audiomode", "audiomode:i:2".to_string()),
        ("audiocapturemode", "audiocapturemode:i:0".to_string()),
        ("redirectclipboard", "redirectclipboard:i:0".to_string()),
        ("redirectprinters", "redirectprinters:i:0".to_string()),
        ("redirectcomports", "redirectcomports:i:0".to_string()),
        ("redirectsmartcards", "redirectsmartcards:i:0".to_string()),
        ("redirectdrives", "redirectdrives:i:0".to_string()),
        ("redirectwebauthn", "redirectwebauthn:i:0".to_string()),
        ("devicestoredirect", "devicestoredirect:s:".to_string()),
        ("drivestoredirect", "drivestoredirect:s:".to_string()),
        ("camerastoredirect", "camerastoredirect:s:".to_string()),
        (
            "usbdevicestoredirect",
            "usbdevicestoredirect:s:".to_string(),
        ),
        (
            "authentication level",
            "authentication level:i:2".to_string(),
        ),
        (
            "enablecredsspsupport",
            "enablecredsspsupport:i:1".to_string(),
        ),
        (
            "negotiate security layer",
            "negotiate security layer:i:1".to_string(),
        ),
        (
            "prompt for credentials on client",
            "prompt for credentials on client:i:0".to_string(),
        ),
        (
            "disableconnectionsharing",
            "disableconnectionsharing:i:1".to_string(),
        ),
        (
            "autoreconnection enabled",
            "autoreconnection enabled:i:0".to_string(),
        ),
    ];
    let drop_keys = [
        "alternate shell",
        "shell working directory",
        "connect to console",
        "bookmarktype",
        "use redirection server name",
        "forcehidpioptimizations",
        "desktopscalefactor",
        "devicescalefactor",
        "hidef color depth",
        "selectedmonitors",
        "span monitors",
    ];

    Some(rewrite_rdp_config(content, &overrides, &drop_keys))
}

fn rewrite_rdp_config(content: &str, overrides: &[(&str, String)], drop_keys: &[&str]) -> String {
    let mut output = Vec::new();
    let mut applied = vec![false; overrides.len()];

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let key = rdp_line_key(trimmed);
        if drop_keys
            .iter()
            .any(|drop_key| key.eq_ignore_ascii_case(drop_key))
        {
            continue;
        }

        if let Some(index) = overrides
            .iter()
            .position(|(override_key, _)| key.eq_ignore_ascii_case(override_key))
        {
            if !applied[index] {
                output.push(overrides[index].1.clone());
                applied[index] = true;
            }
            continue;
        }

        output.push(trimmed.to_string());
    }

    for (index, (_, line)) in overrides.iter().enumerate() {
        if !applied[index] {
            output.push(line.clone());
        }
    }

    output.join("\n")
}

fn rdp_line_key(line: &str) -> &str {
    line.split_once(':')
        .map(|(key, _)| key)
        .unwrap_or(line)
        .trim()
}

fn build_mstsc_legacy_graphics_rdp_config(content: &str) -> Option<String> {
    let full_address = rdp_setting_value(content, "full address")?;
    let username = rdp_setting_value(content, "username")?;

    if full_address.trim().is_empty() || username.trim().is_empty() {
        return None;
    }

    let lines = [
        format!("full address:s:{}", full_address.trim()),
        format!("username:s:{}", username.trim()),
        "desktopwidth:i:1280".to_string(),
        "desktopheight:i:720".to_string(),
        "screen mode id:i:1".to_string(),
        "session bpp:i:16".to_string(),
        "compression:i:1".to_string(),
        "connection type:i:1".to_string(),
        "networkautodetect:i:0".to_string(),
        "bandwidthautodetect:i:0".to_string(),
        "smart sizing:i:1".to_string(),
        "dynamic resolution:i:0".to_string(),
        "use multimon:i:0".to_string(),
        "use multitransport:i:0".to_string(),
        "bitmapcachepersistenable:i:0".to_string(),
        "font smoothing:i:0".to_string(),
        "disable wallpaper:i:1".to_string(),
        "disable full window drag:i:1".to_string(),
        "disable menu anims:i:1".to_string(),
        "disable themes:i:1".to_string(),
        "audiomode:i:2".to_string(),
        "audiocapturemode:i:0".to_string(),
        "videoplaybackmode:i:0".to_string(),
        "redirectclipboard:i:0".to_string(),
        "redirectprinters:i:0".to_string(),
        "redirectcomports:i:0".to_string(),
        "redirectsmartcards:i:0".to_string(),
        "redirectdrives:i:0".to_string(),
        "devicestoredirect:s:".to_string(),
        "drivestoredirect:s:".to_string(),
        "camerastoredirect:s:".to_string(),
        "usbdevicestoredirect:s:".to_string(),
        "authentication level:i:2".to_string(),
        "enablecredsspsupport:i:1".to_string(),
        "negotiate security layer:i:1".to_string(),
        "prompt for credentials on client:i:0".to_string(),
        "disableconnectionsharing:i:1".to_string(),
        "autoreconnection enabled:i:0".to_string(),
    ];

    Some(lines.join("\n"))
}

fn build_mac_microsoft_remote_desktop_rdp_config(content: &str) -> Option<String> {
    let full_address = rdp_setting_value(content, "full address")?;
    let username = rdp_setting_value(content, "username")?;
    let server_address = swift_server_address(full_address.trim());

    if server_address.is_empty() || username.trim().is_empty() {
        return None;
    }

    let lines = [
        format!("full address:s:{server_address}"),
        format!("username:s:{}", username.trim()),
        "desktopwidth:i:2880".to_string(),
        "desktopheight:i:1620".to_string(),
        "session bpp:i:32".to_string(),
        "forcehidpioptimizations:i:1".to_string(),
        "desktopscalefactor:i:150".to_string(),
        "hidef color depth:i:32".to_string(),
        "compression:i:1".to_string(),
        "font smoothing:i:1".to_string(),
        "disable wallpaper:i:0".to_string(),
        "disable menu anims:i:1".to_string(),
        "disable themes:i:0".to_string(),
        "audiomode:i:0".to_string(),
        "smart sizing:i:1".to_string(),
        "screen mode id:i:2".to_string(),
    ];

    Some(lines.join("\n"))
}

fn build_swift_compatible_mstsc_rdp_config(content: &str) -> Option<String> {
    let full_address = rdp_setting_value(content, "full address")?;
    let username = rdp_setting_value(content, "username")?;
    let server_address = swift_server_address(full_address.trim());

    if server_address.is_empty() || username.trim().is_empty() {
        return None;
    }

    let lines = [
        format!("full address:s:{server_address}"),
        format!("username:s:{}", username.trim()),
        "desktopwidth:i:2880".to_string(),
        "desktopheight:i:1620".to_string(),
        "session bpp:i:24".to_string(),
        "forcehidpioptimizations:i:1".to_string(),
        "desktopscalefactor:i:150".to_string(),
        "hidef color depth:i:24".to_string(),
        "compression:i:1".to_string(),
        "font smoothing:i:1".to_string(),
        "disable wallpaper:i:0".to_string(),
        "disable menu anims:i:1".to_string(),
        "disable themes:i:0".to_string(),
        "audiomode:i:0".to_string(),
        "smart sizing:i:1".to_string(),
        "screen mode id:i:2".to_string(),
    ];

    Some(lines.join("\n"))
}

fn build_template_based_mstsc_rdp_config(content: &str) -> Option<String> {
    let full_address = rdp_setting_value(content, "full address")?;
    let username = rdp_setting_value(content, "username")?;

    if full_address.trim().is_empty() || username.trim().is_empty() {
        return None;
    }

    let template = read_text_file_lossy(&template_rdp_path()).ok()?;
    Some(apply_rdp_template(
        &template,
        full_address.trim(),
        username.trim(),
    ))
}

fn apply_rdp_template(template: &str, full_address: &str, username: &str) -> String {
    let mut output = Vec::new();
    let mut saw_full_address = false;
    let mut saw_username = false;

    for line in template.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let key = trimmed
            .split_once(':')
            .map(|(key, _)| key)
            .unwrap_or(trimmed);
        if key.eq_ignore_ascii_case("full address") {
            output.push(format!("full address:s:{full_address}"));
            saw_full_address = true;
            continue;
        }
        if key.eq_ignore_ascii_case("username") {
            output.push(format!("username:s:{username}"));
            saw_username = true;
            continue;
        }
        if should_drop_template_rdp_line(trimmed) {
            continue;
        }

        output.push(trimmed.to_string());
    }

    if !saw_full_address {
        output.insert(0, format!("full address:s:{full_address}"));
        saw_full_address = true;
    }
    if !saw_username {
        let insert_at = if saw_full_address { 1 } else { 0 };
        output.insert(insert_at, format!("username:s:{username}"));
    }

    output.join("\n")
}

fn should_drop_template_rdp_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.starts_with("password")
        || lower.starts_with("gatewayaccesstoken")
        || lower.starts_with("gatewaycredentialssource")
        || lower.starts_with("gatewayusername")
}

fn swift_server_address(full_address: &str) -> &str {
    full_address
        .split_once(':')
        .map(|(host, _)| host)
        .unwrap_or(full_address)
        .trim()
}

fn rdp_setting_value<'a>(content: &'a str, wanted_key: &str) -> Option<&'a str> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let mut parts = trimmed.splitn(3, ':');
        let key = parts.next()?;
        let second = parts.next()?;
        let value = parts.next().unwrap_or(second);

        if key.eq_ignore_ascii_case(wanted_key) {
            return Some(value);
        }
    }

    None
}

fn has_jumpserver_token_username(content: &str) -> bool {
    content
        .lines()
        .any(|line| line.to_ascii_lowercase().starts_with("username:s:") && line.contains('|'))
}

fn rdp_credential_targets(address: &str) -> Vec<String> {
    let trimmed = address.trim();
    let host = trimmed
        .rsplit_once(':')
        .and_then(|(host, port)| port.parse::<u16>().ok().map(|_| host))
        .unwrap_or(trimmed);

    let mut targets = vec![format!("TERMSRV/{host}")];
    let with_port = format!("TERMSRV/{trimmed}");
    if !targets.contains(&with_port) {
        targets.push(with_port);
    }
    targets
}

fn decode_embedded_rdp_config(content: &str) -> Result<(String, bool)> {
    let normalized_content = unescape_rdp_line_breaks(content);
    if looks_like_rdp(&normalized_content) {
        return Ok((normalized_content, false));
    }

    let compact = content.trim();
    if !looks_like_base64(compact) {
        return Ok((content.to_string(), false));
    }

    let decoded = base64_decode_lossy_tail(compact)?;
    let decoded = String::from_utf8(decoded).map_err(|err| {
        LauncherError::Message(format!("embedded RDP config is not UTF-8: {err}"))
    })?;
    let decoded = unescape_rdp_line_breaks(&decoded);

    if looks_like_rdp(&decoded) {
        Ok((decoded, true))
    } else {
        Ok((content.to_string(), false))
    }
}

fn unescape_rdp_line_breaks(content: &str) -> String {
    content
        .replace("\\r\\n", "\n")
        .replace("\\n", "\n")
        .replace("\\r", "\n")
}

fn looks_like_rdp(content: &str) -> bool {
    content
        .lines()
        .take(12)
        .any(|line| line.starts_with("full address:s:") || line.starts_with("username:s:"))
}

fn looks_like_base64(content: &str) -> bool {
    let trimmed = content.trim();
    trimmed.len() >= 16
        && trimmed.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'+' | b'/' | b'-' | b'_' | b'=' | b'\r' | b'\n' | b'\t' | b' '
                )
        })
}

fn rdp_preview(content: &str) -> String {
    content
        .lines()
        .take(8)
        .map(redact_rdp_line)
        .collect::<Vec<_>>()
        .join(" | ")
}

fn redact_rdp_content(content: &str) -> String {
    content
        .lines()
        .map(redact_rdp_line)
        .collect::<Vec<_>>()
        .join("\n")
}

fn redact_rdp_line(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    if lower.starts_with("username:s:") {
        return redact_username_line(line);
    }
    let sensitive = [
        "password",
        "token",
        "gatewaycredentialssource",
        "gatewayaccesstoken",
        "loadbalanceinfo",
    ];
    if sensitive.iter().any(|key| lower.contains(key)) {
        if let Some(index) = line.rfind(':') {
            format!("{}:<redacted>", &line[..index])
        } else {
            "<redacted>".to_string()
        }
    } else {
        line.to_string()
    }
}

fn redact_username_line(line: &str) -> String {
    if let Some((before_token, _token)) = line.split_once('|') {
        format!("{before_token}|<redacted>")
    } else {
        line.to_string()
    }
}

fn redact_username_value(value: &str) -> String {
    if let Some((before_token, _token)) = value.split_once('|') {
        format!("{before_token}|<redacted>")
    } else {
        value.to_string()
    }
}

fn get_string<'a>(object: &'a BTreeMap<String, JsonValue>, key: &str) -> Option<&'a str> {
    match object.get(key) {
        Some(JsonValue::String(value)) => Some(value),
        _ => None,
    }
}

fn write_rdp_file(name: &str, content: &str) -> Result<PathBuf> {
    let dir = app_config_dir();
    fs::create_dir_all(&dir)?;
    cleanup_old_rdp_files(&dir)?;

    let file_name = format!("{}.rdp", sanitize_file_stem(name));
    let path = dir.join(file_name);
    let normalized = normalize_rdp_newlines(content);
    fs::write(&path, normalized.as_bytes())?;
    Ok(path)
}

fn cleanup_old_rdp_files(dir: &Path) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("rdp"))
            == Some(true)
        {
            let _ = fs::remove_file(path);
        }
    }
    Ok(())
}

fn install_template_rdp(source: &Path, log_path: &Path) -> Result<()> {
    let content = read_text_file_lossy(source)?;
    if rdp_setting_value(&content, "full address").is_none() {
        return Err(LauncherError::Message(format!(
            "template is not an RDP file with full address: {}",
            source.display()
        )));
    }

    let destination = template_rdp_path();
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&destination, normalize_rdp_newlines(&content).as_bytes())?;
    append_log(
        log_path,
        &format!(
            "installed MSTSC template from {} to {}",
            source.display(),
            destination.display()
        ),
    )?;
    println!("Installed MSTSC template: {}", destination.display());
    Ok(())
}

fn clear_template_rdp(log_path: &Path) -> Result<()> {
    let path = template_rdp_path();
    if path.exists() {
        fs::remove_file(&path)?;
        append_log(
            log_path,
            &format!("removed MSTSC template: {}", path.display()),
        )?;
        println!("Removed MSTSC template: {}", path.display());
    } else {
        append_log(log_path, "MSTSC template already absent")?;
        println!("MSTSC template is already absent");
    }
    Ok(())
}

fn template_rdp_path() -> PathBuf {
    app_config_dir().join(TEMPLATE_RDP_FILE_NAME)
}

fn read_text_file_lossy(path: &Path) -> Result<String> {
    let bytes = fs::read(path)?;
    if bytes.starts_with(&[0xff, 0xfe]) {
        let words = bytes[2..]
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        return String::from_utf16(&words).map_err(|err| {
            LauncherError::Message(format!("{} is not valid UTF-16LE: {err}", path.display()))
        });
    }
    if bytes.starts_with(&[0xfe, 0xff]) {
        let words = bytes[2..]
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        return String::from_utf16(&words).map_err(|err| {
            LauncherError::Message(format!("{} is not valid UTF-16BE: {err}", path.display()))
        });
    }
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return String::from_utf8(bytes[3..].to_vec()).map_err(|err| {
            LauncherError::Message(format!("{} is not valid UTF-8: {err}", path.display()))
        });
    }

    String::from_utf8(bytes).map_err(|err| {
        LauncherError::Message(format!(
            "{} is not valid UTF-8/UTF-16 RDP text: {err}",
            path.display()
        ))
    })
}

fn normalize_rdp_newlines(content: &str) -> String {
    let without_crlf = content.replace("\r\n", "\n").replace('\r', "\n");
    without_crlf.replace('\n', "\r\n")
}

fn sanitize_file_stem(name: &str) -> String {
    let mut output = String::with_capacity(name.len().min(80));
    for ch in name.chars() {
        let invalid =
            matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') || ch.is_control();
        output.push(if invalid { '_' } else { ch });
        if output.len() >= 80 {
            break;
        }
    }
    let output = output.trim().trim_end_matches(['.', ' ']).to_string();
    if output.is_empty() {
        "jumpserver-rdp".to_string()
    } else {
        output
    }
}

#[allow(clippy::too_many_arguments)]
fn launch_rdp(
    path: &Path,
    content: Option<&str>,
    token_password: Option<&str>,
    mstsc_override: Option<&Path>,
    no_wait: bool,
    direct_mstsc: bool,
    use_cmdkey: bool,
    monitor_seconds: u64,
    log_path: &Path,
) -> Result<()> {
    if !path.exists() {
        return Err(LauncherError::Message(format!(
            "RDP file does not exist: {}",
            path.display()
        )));
    }
    #[cfg(not(target_os = "windows"))]
    let _ = direct_mstsc;

    let installed_credentials = if use_cmdkey {
        prepare_windows_mstsc_credentials(content, token_password, log_path)
    } else {
        log_cmdkey_disabled(content, log_path);
        Vec::new()
    };

    #[cfg(target_os = "windows")]
    if mstsc_override.is_none() && !direct_mstsc {
        append_log(
            log_path,
            &format!("launch command: ShellExecuteW open {}", path.display()),
        )?;
        log_windows_shell_environment(log_path);
        if let Err(err) = shell_open_rdp_file(path, log_path) {
            cleanup_windows_mstsc_credentials(&installed_credentials, log_path);
            return Err(err);
        }

        if no_wait {
            append_log(log_path, "ShellExecuteW returned; --no-wait is active")?;
            if !installed_credentials.is_empty() {
                append_log(
                    log_path,
                    "cmdkey cleanup deferred because --no-wait is active",
                )?;
            }
        } else {
            append_log(log_path, "ShellExecuteW returned success")?;
            if !installed_credentials.is_empty() {
                append_log(
                    log_path,
                    "cmdkey cleanup delayed until after RDP event monitoring",
                )?;
            }
            monitor_rdp_events_after_mstsc_returns(log_path, monitor_seconds);
            cleanup_windows_mstsc_credentials(&installed_credentials, log_path);
        }
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    let program = mstsc_override
        .map(PathBuf::from)
        .unwrap_or_else(native_windows_mstsc_path);

    #[cfg(target_os = "macos")]
    let program = mstsc_override
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("open"));

    #[cfg(all(unix, not(target_os = "macos")))]
    let program = mstsc_override
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("xdg-open"));

    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = Command::new(&program);
        command.arg(path);
        command
    };

    #[cfg(not(target_os = "windows"))]
    let mut command = {
        let mut command = Command::new(&program);
        command.arg(path);
        command
    };

    append_log(
        log_path,
        &format!("launch command: {} {}", program.display(), path.display()),
    )?;
    log_windows_mstsc_environment(log_path, &program);

    if no_wait {
        let child = command.spawn()?;
        append_log(log_path, &format!("spawned process id {}", child.id()))?;
        if !installed_credentials.is_empty() {
            append_log(
                log_path,
                "cmdkey cleanup deferred because --no-wait is active",
            )?;
        }
    } else {
        let status = command.status()?;
        append_log(log_path, &format!("process exit status: {status}"))?;
        if !installed_credentials.is_empty() {
            append_log(
                log_path,
                "cmdkey cleanup delayed until after RDP event monitoring",
            )?;
        }
        monitor_rdp_events_after_mstsc_returns(log_path, monitor_seconds);
        cleanup_windows_mstsc_credentials(&installed_credentials, log_path);
        if !status.success() {
            return Err(LauncherError::Message(format!(
                "RDP client exited with {status}"
            )));
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
#[link(name = "shell32")]
unsafe extern "system" {
    fn ShellExecuteW(
        hwnd: *mut std::ffi::c_void,
        lp_operation: *const u16,
        lp_file: *const u16,
        lp_parameters: *const u16,
        lp_directory: *const u16,
        n_show_cmd: i32,
    ) -> *mut std::ffi::c_void;
}

#[cfg(target_os = "windows")]
fn shell_open_rdp_file(path: &Path, log_path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;

    let operation: Vec<u16> = "open".encode_utf16().chain(std::iter::once(0)).collect();
    let file: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
        )
    };
    let code = result as isize;
    append_log(log_path, &format!("ShellExecuteW result code: {code}"))?;
    if code <= 32 {
        return Err(LauncherError::Message(format!(
            "ShellExecuteW failed with code {code}"
        )));
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn prepare_windows_mstsc_credentials(
    content: Option<&str>,
    token_password: Option<&str>,
    log_path: &Path,
) -> Vec<String> {
    let Some(content) = content else {
        return Vec::new();
    };
    if !has_jumpserver_token_username(content) {
        return Vec::new();
    }

    let Some(address) = rdp_setting_value(content, "full address") else {
        let _ = append_log(log_path, "cmdkey install skipped: full address missing");
        return Vec::new();
    };
    let Some(username) = rdp_setting_value(content, "username") else {
        let _ = append_log(log_path, "cmdkey install skipped: username missing");
        return Vec::new();
    };

    // JumpServer's razor RDP gateway authenticates with password = token.value.
    // Without it a login is guaranteed to be dropped, so skip (and say why)
    // rather than install a useless blank credential.
    let password = match token_password {
        Some(password) if !password.is_empty() => password,
        _ => {
            let _ = append_log(
                log_path,
                "cmdkey install skipped: jms payload carries no token.value secret; JumpServer requires password=token.value and will reject a blank login",
            );
            return Vec::new();
        }
    };

    let mut installed = Vec::new();
    for target in rdp_credential_targets(address) {
        match Command::new("cmdkey")
            .arg(format!("/generic:{target}"))
            .arg(format!("/user:{}", username.trim()))
            .arg(format!("/pass:{password}"))
            .output()
        {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                let _ = append_log(
                    log_path,
                    &format!(
                        "cmdkey install target={target}, user={}, password_mode=token.value, status={}, stdout={}, stderr={}",
                        redact_username_value(username.trim()),
                        output.status,
                        stdout.trim(),
                        stderr.trim()
                    ),
                );
                if output.status.success() {
                    installed.push(target);
                }
            }
            Err(err) => {
                let _ = append_log(
                    log_path,
                    &format!("cmdkey install target={target} failed: {err}"),
                );
            }
        }
    }

    installed
}

fn log_cmdkey_disabled(content: Option<&str>, log_path: &Path) {
    if content.is_some_and(has_jumpserver_token_username) {
        let _ = append_log(log_path, "cmdkey install skipped: disabled by --no-cmdkey");
    }
}

#[cfg(not(target_os = "windows"))]
fn prepare_windows_mstsc_credentials(
    _content: Option<&str>,
    _token_password: Option<&str>,
    _log_path: &Path,
) -> Vec<String> {
    Vec::new()
}

#[cfg(target_os = "windows")]
fn cleanup_windows_mstsc_credentials(targets: &[String], log_path: &Path) {
    for target in targets {
        match Command::new("cmdkey")
            .arg(format!("/delete:{target}"))
            .output()
        {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                let _ = append_log(
                    log_path,
                    &format!(
                        "cmdkey cleanup target={target}, status={}, stdout={}, stderr={}",
                        output.status,
                        stdout.trim(),
                        stderr.trim()
                    ),
                );
            }
            Err(err) => {
                let _ = append_log(
                    log_path,
                    &format!("cmdkey cleanup target={target} failed: {err}"),
                );
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn cleanup_windows_mstsc_credentials(_targets: &[String], _log_path: &Path) {}

#[cfg(target_os = "windows")]
fn native_windows_mstsc_path() -> PathBuf {
    let candidates = [
        r"C:\Windows\Sysnative\mstsc.exe",
        r"C:\Windows\System32\mstsc.exe",
        r"C:\Windows\SysWOW64\mstsc.exe",
    ];

    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
        .unwrap_or_else(|| PathBuf::from("mstsc.exe"))
}

#[cfg(target_os = "windows")]
fn log_windows_shell_environment(log_path: &Path) {
    let architecture = env::var("PROCESSOR_ARCHITECTURE").unwrap_or_else(|_| "<unset>".to_string());
    let wow64_architecture =
        env::var("PROCESSOR_ARCHITEW6432").unwrap_or_else(|_| "<unset>".to_string());
    let arm64_program_files = env::var("ProgramW6432").unwrap_or_else(|_| "<unset>".to_string());
    let _ = append_log(
        log_path,
        &format!(
            "windows env: PROCESSOR_ARCHITECTURE={architecture}, PROCESSOR_ARCHITEW6432={wow64_architecture}, ProgramW6432={arm64_program_files}, selected_mstsc=<shell .rdp association>"
        ),
    );
}

#[cfg(target_os = "windows")]
fn log_windows_mstsc_environment(log_path: &Path, program: &Path) {
    let architecture = env::var("PROCESSOR_ARCHITECTURE").unwrap_or_else(|_| "<unset>".to_string());
    let wow64_architecture =
        env::var("PROCESSOR_ARCHITEW6432").unwrap_or_else(|_| "<unset>".to_string());
    let arm64_program_files = env::var("ProgramW6432").unwrap_or_else(|_| "<unset>".to_string());
    let _ = append_log(
        log_path,
        &format!(
            "windows env: PROCESSOR_ARCHITECTURE={architecture}, PROCESSOR_ARCHITEW6432={wow64_architecture}, ProgramW6432={arm64_program_files}, selected_mstsc={}",
            program.display()
        ),
    );
}

#[cfg(not(target_os = "windows"))]
fn log_windows_mstsc_environment(_log_path: &Path, _program: &Path) {}

#[cfg(target_os = "windows")]
fn monitor_rdp_events_after_mstsc_returns(log_path: &Path, monitor_seconds: u64) {
    capture_rdp_event_logs(log_path, "immediate after mstsc returned");
    if monitor_seconds == 0 {
        return;
    }
    let _ = append_log(
        log_path,
        &format!("waiting {monitor_seconds}s for delayed RDP disconnect events"),
    );
    std::thread::sleep(std::time::Duration::from_secs(monitor_seconds));
    capture_rdp_event_logs(log_path, "after monitor delay");
}

#[cfg(not(target_os = "windows"))]
fn monitor_rdp_events_after_mstsc_returns(_log_path: &Path, _monitor_seconds: u64) {}

#[cfg(target_os = "windows")]
fn capture_rdp_event_logs(log_path: &Path, label: &str) {
    let channels = [
        "Microsoft-Windows-TerminalServices-RDPClient/Operational",
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
        "Microsoft-Windows-TerminalServices-ClientUSBDevices/Operational",
        "Application",
        "System",
    ];
    let query = "*[System[TimeCreated[timediff(@SystemTime) <= 180000]]]";
    for channel in channels {
        let _ = append_log(
            log_path,
            &format!("querying Windows event log ({label}, recent 180s): {channel}"),
        );
        match Command::new("wevtutil")
            .args(["qe", channel])
            .arg(format!("/q:{query}"))
            .args(["/rd:true", "/c:30", "/f:xml"])
            .output()
        {
            Ok(output) => {
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let _ = append_log(
                        log_path,
                        &format!(
                            "event log query failed for {channel}: status={}, stderr={}",
                            output.status,
                            redact_event_log(stderr.trim())
                        ),
                    );
                    continue;
                }
                let stdout = String::from_utf8_lossy(&output.stdout);
                let trimmed = stdout.trim();
                if trimmed.is_empty() {
                    let _ = append_log(log_path, &format!("event log {channel}: <empty>"));
                } else {
                    let _ = append_multiline_log(
                        log_path,
                        &format!("event log {channel}"),
                        &redact_event_log(trimmed),
                    );
                }
            }
            Err(err) => {
                let _ = append_log(
                    log_path,
                    &format!("event log query failed for {channel}: {err}"),
                );
            }
        }
    }
}

fn register_protocol(
    log_path: &Path,
    profile: Option<&str>,
    direct_mstsc: bool,
    use_cmdkey: bool,
) -> Result<()> {
    let exe = env::current_exe()?;
    let mut command_parts = vec![format!("\"{}\"", exe.display())];
    if let Some(profile) = profile {
        if profile != DEFAULT_RDP_PROFILE {
            command_parts.push(format!("--profile {profile}"));
        }
    }
    if direct_mstsc {
        command_parts.push("--direct-mstsc".to_string());
    }
    if use_cmdkey {
        command_parts.push("--use-cmdkey".to_string());
    } else {
        command_parts.push("--no-cmdkey".to_string());
    }
    command_parts.push("\"%1\"".to_string());
    let command_value = command_parts.join(" ");
    append_log(
        log_path,
        &format!("registering jms protocol to {command_value}"),
    )?;

    #[cfg(target_os = "windows")]
    {
        run_reg(&[
            "add",
            r"HKCU\Software\Classes\jms",
            "/ve",
            "/d",
            "URL:JumpServer JMS Protocol",
            "/f",
        ])?;
        run_reg(&[
            "add",
            r"HKCU\Software\Classes\jms",
            "/v",
            "URL Protocol",
            "/t",
            "REG_SZ",
            "/d",
            "",
            "/f",
        ])?;
        run_reg(&[
            "add",
            r"HKCU\Software\Classes\jms\shell\open\command",
            "/ve",
            "/d",
            &command_value,
            "/f",
        ])?;
        println!("Registered jms:// to {}", exe.display());
    }

    #[cfg(not(target_os = "windows"))]
    {
        println!("Run this in Windows to register the protocol:");
        println!(r#"reg add HKCU\Software\Classes\jms /ve /d "URL:JumpServer JMS Protocol" /f"#);
        println!(r#"reg add HKCU\Software\Classes\jms /v "URL Protocol" /t REG_SZ /d "" /f"#);
        println!(
            r#"reg add HKCU\Software\Classes\jms\shell\open\command /ve /d "{}" /f"#,
            command_value
        );
    }

    Ok(())
}

fn unregister_protocol(log_path: &Path) -> Result<()> {
    append_log(log_path, "unregistering jms protocol")?;

    #[cfg(target_os = "windows")]
    {
        run_reg(&["delete", r"HKCU\Software\Classes\jms", "/f"])?;
        println!("Unregistered current-user jms:// handler");
    }

    #[cfg(not(target_os = "windows"))]
    {
        println!(r#"Run this in Windows: reg delete HKCU\Software\Classes\jms /f"#);
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn run_reg(args: &[&str]) -> Result<()> {
    let status = Command::new("reg").args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(LauncherError::Message(format!(
            "reg.exe failed with {status}"
        )))
    }
}

fn app_config_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Some(appdata) = env::var_os("APPDATA") {
            return PathBuf::from(appdata).join("jms-rdp-launcher");
        }
        if let Some(profile) = env::var_os("USERPROFILE") {
            return PathBuf::from(profile)
                .join("AppData")
                .join("Roaming")
                .join("jms-rdp-launcher");
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Some(xdg) = env::var_os("XDG_CONFIG_HOME") {
            return PathBuf::from(xdg).join("jms-rdp-launcher");
        }
        if let Some(home) = env::var_os("HOME") {
            return PathBuf::from(home).join(".config").join("jms-rdp-launcher");
        }
    }

    PathBuf::from(".").join("jms-rdp-launcher")
}

fn default_log_path() -> PathBuf {
    app_config_dir().join("launcher.log")
}

fn append_log(path: &Path, message: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "[{}] {}", timestamp(), message)?;
    Ok(())
}

fn append_multiline_log(path: &Path, title: &str, body: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let timestamp = timestamp();
    writeln!(file, "[{timestamp}] {title}:")?;
    for line in body.lines() {
        writeln!(file, "[{timestamp}]   {line}")?;
    }
    Ok(())
}

fn timestamp() -> String {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => format!("unix:{}", duration.as_secs()),
        Err(_) => "unix:0".to_string(),
    }
}

fn redact_long(value: &str, max: usize) -> String {
    if value.len() <= max {
        value.to_string()
    } else {
        format!("{}...<{} chars total>", &value[..max], value.len())
    }
}

fn redact_event_log(text: &str) -> String {
    text.lines()
        .map(redact_pipe_token_segment)
        .collect::<Vec<_>>()
        .join("\n")
}

fn redact_pipe_token_segment(line: &str) -> String {
    let Some(pipe_index) = line.find('|') else {
        return line.to_string();
    };

    let mut output = String::with_capacity(line.len());
    output.push_str(&line[..pipe_index]);
    output.push('|');
    output.push_str("<redacted>");

    let after_pipe = &line[pipe_index + 1..];
    let keep_from = after_pipe
        .char_indices()
        .find_map(|(index, ch)| {
            if ch.is_ascii_whitespace() || matches!(ch, '"' | '\'' | ')' | ']' | ',' | ';') {
                Some(index)
            } else {
                None
            }
        })
        .unwrap_or(after_pipe.len());
    output.push_str(&after_pipe[keep_from..]);
    output
}

fn percent_decode(input: &str) -> Result<String> {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(LauncherError::Message(
                    "bad percent escape at end of input".to_string(),
                ));
            }
            let hi = hex_value(bytes[index + 1])?;
            let lo = hex_value(bytes[index + 2])?;
            output.push((hi << 4) | lo);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output)
        .map_err(|err| LauncherError::Message(format!("percent-decoded input is not UTF-8: {err}")))
}

fn hex_value(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(LauncherError::Message(format!(
            "bad percent escape: {}",
            byte as char
        ))),
    }
}

fn base64_decode(input: &str) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u8;
    let mut seen_padding = false;

    for byte in input.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        if byte == b'=' {
            seen_padding = true;
            continue;
        }
        if seen_padding {
            return Err(LauncherError::Message(
                "base64 data after padding".to_string(),
            ));
        }

        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'-' => 62,
            b'_' => 63,
            _ => {
                return Err(LauncherError::Message(format!(
                    "invalid base64 byte: {}",
                    byte as char
                )))
            }
        } as u32;

        buffer = (buffer << 6) | value;
        bits += 6;
        while bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xff) as u8);
        }
    }

    Ok(output)
}

fn base64_decode_lossy_tail(input: &str) -> Result<Vec<u8>> {
    match base64_decode(input) {
        Ok(decoded) => Ok(decoded),
        Err(LauncherError::Message(message)) if message == "base64 data after padding" => {
            let trimmed = trim_after_base64_padding(input);
            base64_decode(trimmed)
        }
        Err(err) => Err(err),
    }
}

fn trim_after_base64_padding(input: &str) -> &str {
    let Some(first_padding) = input.find('=') else {
        return input;
    };
    let mut end = first_padding;
    for (offset, ch) in input[first_padding..].char_indices() {
        if ch == '=' || ch.is_ascii_whitespace() {
            end = first_padding + offset + ch.len_utf8();
        } else {
            break;
        }
    }
    &input[..end]
}

struct JsonParser<'a> {
    input: &'a str,
    bytes: &'a [u8],
    index: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            bytes: input.as_bytes(),
            index: 0,
        }
    }

    fn parse(mut self) -> Result<JsonValue> {
        let value = self.parse_value()?;
        self.skip_ws();
        if self.index != self.bytes.len() {
            return Err(self.error("unexpected trailing JSON data"));
        }
        Ok(value)
    }

    fn parse_value(&mut self) -> Result<JsonValue> {
        self.skip_ws();
        match self.peek() {
            Some(b'n') => self.parse_literal("null", JsonValue::Null),
            Some(b't') => self.parse_literal("true", JsonValue::Bool(true)),
            Some(b'f') => self.parse_literal("false", JsonValue::Bool(false)),
            Some(b'"') => Ok(JsonValue::String(self.parse_string()?)),
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            Some(_) => Err(self.error("unexpected JSON value")),
            None => Err(self.error("unexpected end of JSON")),
        }
    }

    fn parse_literal(&mut self, literal: &str, value: JsonValue) -> Result<JsonValue> {
        if self.input[self.index..].starts_with(literal) {
            self.index += literal.len();
            Ok(value)
        } else {
            Err(self.error("invalid JSON literal"))
        }
    }

    fn parse_object(&mut self) -> Result<JsonValue> {
        self.expect(b'{')?;
        let mut object = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.index += 1;
            return Ok(JsonValue::Object(object));
        }

        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            let value = self.parse_value()?;
            object.insert(key, value);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.index += 1,
                Some(b'}') => {
                    self.index += 1;
                    break;
                }
                _ => return Err(self.error("expected ',' or '}' in object")),
            }
        }
        Ok(JsonValue::Object(object))
    }

    fn parse_array(&mut self) -> Result<JsonValue> {
        self.expect(b'[')?;
        let mut array = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.index += 1;
            return Ok(JsonValue::Array(array));
        }

        loop {
            array.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.index += 1,
                Some(b']') => {
                    self.index += 1;
                    break;
                }
                _ => return Err(self.error("expected ',' or ']' in array")),
            }
        }
        Ok(JsonValue::Array(array))
    }

    fn parse_number(&mut self) -> Result<JsonValue> {
        let start = self.index;
        if self.peek() == Some(b'-') {
            self.index += 1;
        }
        self.consume_digits();
        if self.peek() == Some(b'.') {
            self.index += 1;
            self.consume_digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.index += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.index += 1;
            }
            self.consume_digits();
        }
        if self.index == start {
            return Err(self.error("invalid JSON number"));
        }
        Ok(JsonValue::Number(self.input[start..self.index].to_string()))
    }

    fn consume_digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.index += 1;
        }
    }

    fn parse_string(&mut self) -> Result<String> {
        self.expect(b'"')?;
        let mut output = String::new();

        while let Some(byte) = self.peek() {
            match byte {
                b'"' => {
                    self.index += 1;
                    return Ok(output);
                }
                b'\\' => {
                    self.index += 1;
                    output.push(self.parse_escape()?);
                }
                0x00..=0x1f => return Err(self.error("control character in JSON string")),
                _ => {
                    let remaining = &self.input[self.index..];
                    let ch = remaining
                        .chars()
                        .next()
                        .ok_or_else(|| self.error("invalid UTF-8 in JSON string"))?;
                    self.index += ch.len_utf8();
                    output.push(ch);
                }
            }
        }

        Err(self.error("unterminated JSON string"))
    }

    fn parse_escape(&mut self) -> Result<char> {
        let byte = self
            .peek()
            .ok_or_else(|| self.error("unterminated JSON escape"))?;
        self.index += 1;
        match byte {
            b'"' => Ok('"'),
            b'\\' => Ok('\\'),
            b'/' => Ok('/'),
            b'b' => Ok('\u{0008}'),
            b'f' => Ok('\u{000c}'),
            b'n' => Ok('\n'),
            b'r' => Ok('\r'),
            b't' => Ok('\t'),
            b'u' => self.parse_unicode_escape(),
            _ => Err(self.error("invalid JSON escape")),
        }
    }

    fn parse_unicode_escape(&mut self) -> Result<char> {
        let first = self.parse_u16_hex()?;
        if (0xD800..=0xDBFF).contains(&first) {
            let save = self.index;
            if self.peek() == Some(b'\\') {
                self.index += 1;
                if self.peek() == Some(b'u') {
                    self.index += 1;
                    let second = self.parse_u16_hex()?;
                    if (0xDC00..=0xDFFF).contains(&second) {
                        let high = (first as u32) - 0xD800;
                        let low = (second as u32) - 0xDC00;
                        let codepoint = 0x10000 + ((high << 10) | low);
                        return char::from_u32(codepoint)
                            .ok_or_else(|| self.error("invalid unicode codepoint"));
                    }
                }
            }
            self.index = save;
            return Ok('\u{FFFD}');
        }

        char::from_u32(first as u32).ok_or_else(|| self.error("invalid unicode codepoint"))
    }

    fn parse_u16_hex(&mut self) -> Result<u16> {
        if self.index + 4 > self.bytes.len() {
            return Err(self.error("short unicode escape"));
        }
        let mut value = 0u16;
        for _ in 0..4 {
            value = (value << 4) | hex_value(self.bytes[self.index])? as u16;
            self.index += 1;
        }
        Ok(value)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.index += 1;
        }
    }

    fn expect(&mut self, expected: u8) -> Result<()> {
        if self.peek() == Some(expected) {
            self.index += 1;
            Ok(())
        } else {
            Err(self.error(&format!("expected '{}'", expected as char)))
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }

    fn error(&self, message: &str) -> LauncherError {
        LauncherError::Message(format!("{message} at byte {}", self.index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_base64() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
    }

    #[test]
    fn decodes_percent_encoded_padding() {
        assert_eq!(percent_decode("aGVsbG8%3D").unwrap(), "aGVsbG8=");
    }

    #[test]
    fn parses_json_with_nested_file_content() {
        let json = r#"{
            "protocol": "rdp",
            "name": "ignored",
            "file": {
                "name": "win server",
                "content": "full address:s:127.0.0.1:3389\nusername:s:JMS-abc"
            }
        }"#;
        let parsed = JsonParser::new(json).parse().unwrap();
        let launch = extract_rdp_launch(&parsed, DEFAULT_RDP_PROFILE).unwrap();
        assert_eq!(launch.protocol, "rdp");
        assert_eq!(launch.name, "win server");
        assert!(launch.content.contains("full address:s:127.0.0.1:3389"));
        assert!(launch.content.contains('\n'));
    }

    #[test]
    fn sanitizes_windows_file_names() {
        assert_eq!(
            sanitize_file_stem(r#"a:b<c>d/e\ f|g?h*."#),
            "a_b_c_d_e_ f_g_h_"
        );
    }

    #[test]
    fn parses_jms_link() {
        let payload = r#"{"protocol":"rdp","file":{"name":"vm win","content":"full address:s:10.0.0.1:3389\n"}}"#;
        let encoded = "eyJwcm90b2NvbCI6InJkcCIsImZpbGUiOnsibmFtZSI6InZtIHdpbiIsImNvbnRlbnQiOiJmdWxsIGFkZHJlc3M6czoxMC4wLjAuMTozMzg5XG4ifX0=";
        assert_eq!(base64_decode(encoded).unwrap(), payload.as_bytes());
        let launch = parse_jms_link(&format!("jms://{encoded}"), DEFAULT_RDP_PROFILE).unwrap();
        assert_eq!(launch.protocol, "rdp");
        assert_eq!(launch.name, "vm win");
    }

    #[test]
    fn parse_cli_uses_cmdkey_by_default() {
        let cli = parse_cli(vec!["jms://payload".to_string()]).unwrap();

        assert!(cli.use_cmdkey);
        assert_eq!(cli.monitor_seconds, 30);
    }

    #[test]
    fn parse_cli_no_cmdkey_disables_credentials() {
        let cli = parse_cli(vec![
            "--no-cmdkey".to_string(),
            "jms://payload".to_string(),
        ])
        .unwrap();

        assert!(!cli.use_cmdkey);
    }

    #[test]
    fn parse_cli_accepts_explicit_use_cmdkey() {
        let cli = parse_cli(vec![
            "--use-cmdkey".to_string(),
            "jms://payload".to_string(),
        ])
        .unwrap();

        assert!(cli.use_cmdkey);
    }

    fn token_secret_of(json_text: &str) -> Option<String> {
        match JsonParser::new(json_text).parse().unwrap() {
            JsonValue::Object(object) => extract_token_secret(&object),
            _ => panic!("expected object"),
        }
    }

    #[test]
    fn extracts_token_secret_from_token_object() {
        let secret = token_secret_of(
            r#"{"token":{"id":"a2b904ac","value":"s3cr3t-value"},"protocol":"rdp"}"#,
        );
        assert_eq!(secret.as_deref(), Some("s3cr3t-value"));
    }

    #[test]
    fn extracts_token_secret_from_top_level_value() {
        let secret = token_secret_of(r#"{"value":"top-secret","protocol":"rdp"}"#);
        assert_eq!(secret.as_deref(), Some("top-secret"));
    }

    #[test]
    fn extracts_token_secret_from_token_string() {
        let secret = token_secret_of(r#"{"token":"plain-secret","protocol":"rdp"}"#);
        assert_eq!(secret.as_deref(), Some("plain-secret"));
    }

    #[test]
    fn empty_token_string_yields_no_secret() {
        // Matches the failing real-world payload: token is present but empty.
        let secret = token_secret_of(r#"{"token":"","protocol":"rdp","username":"testuser"}"#);
        assert_eq!(secret, None);
    }

    #[test]
    fn parses_jumpserver_filename_config_payload() {
        let encoded = "eyJmaWxlbmFtZSI6Indpbi10ZXN0IiwicHJvdG9jb2wiOiJyZHAiLCJjb25maWciOiJmdWxsIGFkZHJlc3M6czoxMjcuMC4wLjE6MzM4OVxudXNlcm5hbWU6czp0ZXN0dXNlciJ9/";
        let launch = parse_jms_link(&format!("jms://{encoded}"), DEFAULT_RDP_PROFILE).unwrap();
        assert_eq!(launch.protocol, "rdp");
        assert_eq!(launch.name, "win-test");
        assert!(!launch.inner_config_base64);
        assert!(launch.content.contains("full address:s:127.0.0.1:3389"));
        assert!(launch.content.contains("username:s:testuser"));
    }

    #[test]
    fn decodes_base64_embedded_rdp_config() {
        let encoded = "eyJmaWxlbmFtZSI6Indpbi10ZXN0IiwicHJvdG9jb2wiOiJyZHAiLCJjb25maWciOiJablZzYkNCaFpHUnlaWE56T25NNk1USXlMakF1TUM0eE9qTXpPRGxjYm5WelpYSnVZVzFsT25NNmVXMXBibWNnIn0=/";
        let launch = parse_jms_link(&format!("jms://{encoded}"), DEFAULT_RDP_PROFILE).unwrap();
        assert_eq!(launch.protocol, "rdp");
        assert_eq!(launch.name, "win-test");
        assert!(launch.inner_config_base64);
        assert_eq!(
            launch.content,
            "full address:s:122.0.0.1:3389\nusername:s:yming "
        );
    }

    #[test]
    fn regenerates_swift_compatible_mstsc_config_for_token_username() {
        let content = "\
full address:s:jumpserver.example.com:3389
username:s:testuser|token
use multimon:i:0
session bpp:i:32
authentication level:i:2
prompt for credentials on client:i:0
disableconnectionsharing:i:1";

        let (regenerated, strategy, patches) =
            normalize_jumpserver_rdp_config(content.to_string(), "swift");

        assert_eq!(strategy, "swift_compatible_mstsc");
        assert!(patches.is_empty());
        assert!(regenerated.contains("full address:s:jumpserver.example.com"));
        assert!(!regenerated.contains("full address:s:jumpserver.example.com:3389"));
        assert!(regenerated.contains("username:s:testuser|token"));
        assert!(regenerated.contains("desktopwidth:i:2880"));
        assert!(regenerated.contains("desktopheight:i:1620"));
        assert!(regenerated.contains("session bpp:i:24"));
        assert!(regenerated.contains("forcehidpioptimizations:i:1"));
        assert!(regenerated.contains("desktopscalefactor:i:150"));
        assert!(regenerated.contains("hidef color depth:i:24"));
        assert!(regenerated.contains("compression:i:1"));
        assert!(regenerated.contains("font smoothing:i:1"));
        assert!(!regenerated.contains("authentication level"));
        assert!(!regenerated.contains("prompt for credentials on client"));
        assert!(!regenerated.contains("disableconnectionsharing"));
        assert!(!regenerated.contains("enablecredsspsupport"));
        assert!(!regenerated.contains("use multitransport"));
        assert!(!regenerated.contains("redirectclipboard"));
    }

    #[test]
    fn regenerates_mac_compatible_config_by_default_for_token_username() {
        let content = "\
full address:s:jumpserver.example.com:3389
username:s:testuser|token
use multimon:i:0
session bpp:i:32
audiomode:i:0
forcehidpioptimizations:i:1
desktopscalefactor:i:150
hidef color depth:i:24";

        let (regenerated, strategy, patches) =
            normalize_jumpserver_rdp_config(content.to_string(), DEFAULT_RDP_PROFILE);

        assert_eq!(strategy, "mac_microsoft_remote_desktop_compatible");
        assert!(patches.is_empty());
        assert!(regenerated.contains("full address:s:jumpserver.example.com"));
        assert!(!regenerated.contains("full address:s:jumpserver.example.com:3389"));
        assert!(regenerated.contains("username:s:testuser|token"));
        assert!(regenerated.contains("desktopwidth:i:2880"));
        assert!(regenerated.contains("desktopheight:i:1620"));
        assert!(regenerated.contains("screen mode id:i:2"));
        assert!(regenerated.contains("session bpp:i:32"));
        assert!(regenerated.contains("forcehidpioptimizations:i:1"));
        assert!(regenerated.contains("desktopscalefactor:i:150"));
        assert!(regenerated.contains("hidef color depth:i:32"));
        assert!(regenerated.contains("audiomode:i:0"));
        assert!(!regenerated.contains("authentication level"));
        assert!(!regenerated.contains("prompt for credentials on client"));
        assert!(!regenerated.contains("disableconnectionsharing"));
        assert!(!regenerated.contains("enablecredsspsupport"));
        assert!(!regenerated.contains("use multitransport"));
        assert!(!regenerated.contains("redirectclipboard"));
    }

    #[test]
    fn regenerates_gnome_compatible_config_for_gnome_profile() {
        let content = "\
full address:s:jumpserver.example.com:3389
username:s:testuser|token
use multimon:i:0
session bpp:i:32
audiomode:i:0
forcehidpioptimizations:i:1
desktopscalefactor:i:150
hidef color depth:i:24";

        let (regenerated, strategy, patches) =
            normalize_jumpserver_rdp_config(content.to_string(), "gnome");

        assert_eq!(strategy, "mstsc_gnome_compatible");
        assert!(patches.is_empty());
        assert!(regenerated.contains("full address:s:jumpserver.example.com:3389"));
        assert!(regenerated.contains("username:s:testuser|token"));
        assert!(regenerated.contains("desktopwidth:i:1920"));
        assert!(regenerated.contains("desktopheight:i:1080"));
        assert!(regenerated.contains("screen mode id:i:1"));
        assert!(regenerated.contains("session bpp:i:32"));
        assert!(regenerated.contains("dynamic resolution:i:1"));
        assert!(regenerated.contains("use multitransport:i:0"));
        assert!(regenerated.contains("enablecredsspsupport:i:1"));
        assert!(regenerated.contains("authentication level:i:2"));
        assert!(regenerated.contains("negotiate security layer:i:1"));
        assert!(regenerated.contains("redirectdrives:i:0"));
        assert!(regenerated.contains("redirectwebauthn:i:0"));
        assert!(regenerated.contains("audiomode:i:2"));
        assert!(!regenerated.contains("forcehidpioptimizations"));
        assert!(!regenerated.contains("desktopscalefactor"));
        assert!(!regenerated.contains("hidef color depth"));
    }

    #[test]
    fn template_profile_falls_back_to_mac_config_without_template() {
        let content = "\
full address:s:jumpserver.example.com:3389
username:s:testuser|token
use multimon:i:0
session bpp:i:32
audiomode:i:0";

        let (regenerated, strategy, patches) =
            normalize_jumpserver_rdp_config(content.to_string(), "template");

        if strategy == "mstsc_saved_template" {
            return;
        }

        assert_eq!(strategy, "mac_microsoft_remote_desktop_compatible");
        assert_eq!(patches, vec!["template_not_installed".to_string()]);
        assert!(regenerated.contains("full address:s:jumpserver.example.com"));
        assert!(!regenerated.contains("full address:s:jumpserver.example.com:3389"));
        assert!(regenerated.contains("session bpp:i:32"));
        assert!(regenerated.contains("hidef color depth:i:32"));
        assert!(!regenerated.contains("authentication level"));
    }

    #[test]
    fn applies_saved_mstsc_template_without_credentials() {
        let template = "\
full address:s:ubuntu.local
username:s:ubuntu
session bpp:i:32
use multitransport:i:0
password 51:b:010203
gatewayaccesstoken:s:secret";

        let generated = apply_rdp_template(template, "jumpserver.example.com:3389", "testuser|token");

        assert!(generated.contains("full address:s:jumpserver.example.com:3389"));
        assert!(generated.contains("username:s:testuser|token"));
        assert!(generated.contains("session bpp:i:32"));
        assert!(generated.contains("use multitransport:i:0"));
        assert!(!generated.contains("ubuntu.local"));
        assert!(!generated.contains("password 51:b"));
        assert!(!generated.contains("gatewayaccesstoken"));
    }

    #[test]
    fn regenerates_legacy_graphics_config_for_legacy_profile() {
        let content = "\
full address:s:jumpserver.example.com:3389
username:s:testuser|token
use multimon:i:0
session bpp:i:32
audiomode:i:0";

        let (regenerated, strategy, patches) =
            normalize_jumpserver_rdp_config(content.to_string(), "legacy");

        assert_eq!(strategy, "mstsc_legacy_graphics");
        assert!(patches.is_empty());
        assert!(regenerated.contains("full address:s:jumpserver.example.com:3389"));
        assert!(regenerated.contains("username:s:testuser|token"));
        assert!(regenerated.contains("desktopwidth:i:1280"));
        assert!(regenerated.contains("desktopheight:i:720"));
        assert!(regenerated.contains("screen mode id:i:1"));
        assert!(regenerated.contains("session bpp:i:16"));
        assert!(regenerated.contains("audiomode:i:2"));
        assert!(regenerated.contains("redirectclipboard:i:0"));
        assert!(regenerated.contains("redirectdrives:i:0"));
        assert!(regenerated.contains("use multitransport:i:0"));
        assert!(regenerated.contains("dynamic resolution:i:0"));
        assert!(regenerated.contains("enablecredsspsupport:i:1"));
        assert!(regenerated.contains("negotiate security layer:i:1"));
        assert!(!regenerated.contains("forcehidpioptimizations"));
        assert!(!regenerated.contains("desktopscalefactor"));
    }

    #[test]
    fn raw_profile_keeps_jumpserver_config_unchanged_for_token_username() {
        let content =
            "full address:s:jumpserver.example.com:3389\nusername:s:testuser|token\naudiomode:i:0";

        let (regenerated, strategy, patches) =
            normalize_jumpserver_rdp_config(content.to_string(), "raw");

        assert_eq!(strategy, "raw_jumpserver");
        assert!(patches.is_empty());
        assert_eq!(regenerated, content);
    }

    #[test]
    fn builds_rdp_credential_targets_with_and_without_port() {
        assert_eq!(
            rdp_credential_targets("jumpserver.example.com:3389"),
            vec![
                "TERMSRV/jumpserver.example.com".to_string(),
                "TERMSRV/jumpserver.example.com:3389".to_string()
            ]
        );
        assert_eq!(
            rdp_credential_targets("jumpserver.example.com"),
            vec!["TERMSRV/jumpserver.example.com".to_string()]
        );
    }

    #[test]
    fn redacts_standalone_pipe_username_value() {
        assert_eq!(
            redact_username_value("testuser|e2ab7862-846f-4e96-bfd9-7b0526f28cb1"),
            "testuser|<redacted>"
        );
    }

    #[test]
    fn strips_rdp_port_like_swift_connection_info() {
        let content = "full address:s:jumpserver.example.com:3390\nusername:s:testuser|token";
        let (regenerated, strategy, patches) =
            normalize_jumpserver_rdp_config(content.to_string(), "swift");

        assert_eq!(strategy, "swift_compatible_mstsc");
        assert!(patches.is_empty());
        assert!(regenerated.contains("full address:s:jumpserver.example.com"));
        assert!(!regenerated.contains("full address:s:jumpserver.example.com:3390"));
    }

    #[test]
    fn redacts_sensitive_rdp_preview_lines() {
        let preview = rdp_preview(
            "full address:s:127.0.0.1:3389\nusername:s:testuser|e2ab7862-846f-4e96-bfd9-7b0526f28cb1\npassword 51:b:abc123\ngatewayaccesstoken:s:secret",
        );
        assert!(preview.contains("full address:s:127.0.0.1:3389"));
        assert!(preview.contains("username:s:testuser|<redacted>"));
        assert!(preview.contains("password 51:b:<redacted>"));
        assert!(preview.contains("gatewayaccesstoken:s:<redacted>"));
        assert!(!preview.contains("e2ab7862"));
        assert!(!preview.contains("abc123"));
        assert!(!preview.contains("secret"));
    }

    #[test]
    fn redacts_pipe_token_in_event_log_text() {
        let text = r#"User: testuser|e2ab7862-846f-4e96-bfd9-7b0526f28cb1 disconnected"#;
        let redacted = redact_event_log(text);
        assert_eq!(redacted, "User: testuser|<redacted> disconnected");
    }
}
