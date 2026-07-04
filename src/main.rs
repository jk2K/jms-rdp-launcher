use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, LauncherError>;

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
    log: Option<PathBuf>,
    rdp_file: Option<PathBuf>,
    no_wait: bool,
    help: bool,
}

#[derive(Debug)]
struct RdpLaunch {
    protocol: String,
    name: String,
    content: String,
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
        register_protocol(log_path)?;
        return Ok(());
    }

    if cli.unregister {
        unregister_protocol(log_path)?;
        return Ok(());
    }

    if let Some(rdp_file) = cli.rdp_file {
        append_log(
            log_path,
            &format!("launching existing rdp file: {}", rdp_file.display()),
        )?;
        return launch_rdp(&rdp_file, cli.mstsc.as_deref(), cli.no_wait, log_path);
    }

    let input = cli
        .input
        .ok_or_else(|| LauncherError::Message("missing jms:// input".to_string()))?;
    append_log(
        log_path,
        &format!("raw argument: {}", redact_long(&input, 300)),
    )?;

    let launch = parse_jms_link(&input)?;
    append_log(
        log_path,
        &format!(
            "decoded payload: protocol={}, name={}, rdp_bytes={}",
            launch.protocol,
            launch.name,
            launch.content.len()
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

    launch_rdp(&rdp_path, cli.mstsc.as_deref(), cli.no_wait, log_path)
}

fn parse_cli(args: Vec<String>) -> Result<Cli> {
    let mut cli = Cli::default();
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
            "--mstsc" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| LauncherError::Message("--mstsc requires a path".to_string()))?;
                cli.mstsc = Some(PathBuf::from(value));
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
           --log <path>         Override log path\n\
           --rdp-file <path>    Launch an existing .rdp file\n\
           --no-wait            Spawn mstsc and return immediately\n\
           --register           Register this exe as the jms:// handler for current user\n\
           --unregister         Remove the current-user jms:// registration\n"
    );
}

fn parse_jms_link(input: &str) -> Result<RdpLaunch> {
    let trimmed = input.trim().trim_matches('"').trim_matches('\'');
    let payload = trimmed
        .strip_prefix("jms://")
        .or_else(|| trimmed.strip_prefix("JMS://"))
        .unwrap_or(trimmed);
    let payload = percent_decode(payload)?.replace(' ', "+");
    let decoded = base64_decode(&payload)?;
    let json_text = String::from_utf8(decoded)
        .map_err(|err| LauncherError::Message(format!("decoded payload is not UTF-8: {err}")))?;
    let json = JsonParser::new(&json_text).parse()?;
    extract_rdp_launch(&json)
}

fn extract_rdp_launch(json: &JsonValue) -> Result<RdpLaunch> {
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
        .or_else(|| get_string(object, "name"))
        .unwrap_or("jumpserver-rdp")
        .to_string();

    let content = file
        .and_then(|file| get_string(file, "content"))
        .or_else(|| get_string(object, "content"))
        .ok_or_else(|| LauncherError::Message("payload has no file.content RDP data".to_string()))?
        .to_string();

    Ok(RdpLaunch {
        protocol,
        name,
        content,
    })
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

fn launch_rdp(
    path: &Path,
    mstsc_override: Option<&Path>,
    no_wait: bool,
    log_path: &Path,
) -> Result<()> {
    if !path.exists() {
        return Err(LauncherError::Message(format!(
            "RDP file does not exist: {}",
            path.display()
        )));
    }

    #[cfg(target_os = "windows")]
    let program = mstsc_override
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("mstsc.exe"));

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

    if no_wait {
        let child = command.spawn()?;
        append_log(log_path, &format!("spawned process id {}", child.id()))?;
    } else {
        let status = command.status()?;
        append_log(log_path, &format!("process exit status: {status}"))?;
        if !status.success() {
            return Err(LauncherError::Message(format!(
                "RDP client exited with {status}"
            )));
        }
    }
    Ok(())
}

fn register_protocol(log_path: &Path) -> Result<()> {
    let exe = env::current_exe()?;
    let command_value = format!("\"{}\" \"%1\"", exe.display());
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
        let launch = extract_rdp_launch(&parsed).unwrap();
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
        let launch = parse_jms_link(&format!("jms://{encoded}")).unwrap();
        assert_eq!(launch.protocol, "rdp");
        assert_eq!(launch.name, "vm win");
    }
}
