// SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
// SPDX-License-Identifier: Apache-2.0

//! Kubelet-equivalent HTTP(S) GET and TCP probes against `127.0.0.1`, and the
//! `install` subcommand that copies the helper into a directory a sandbox can mount.

use std::ffi::OsString;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Args, Parser, Subcommand, ValueEnum};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};

const KUBE_USER_AGENT: &str = "kube-probe/odp-probe";
const HELPER_NAME: &str = "odp-probe";

/// A probe or installation failure. Its message is the one-line reason printed on stderr.
#[derive(Debug, thiserror::Error)]
enum ProbeError {
    /// An argument value that cannot be sent in a request or used as given.
    #[error("{0}")]
    Invalid(String),
    /// The TCP connection to the probed port failed.
    #[error("cannot connect to 127.0.0.1:{port}: {source}")]
    Connect { port: u16, source: io::Error },
    /// A read or write on the probe connection failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// The response does not begin with an HTTP status line.
    #[error("response does not start with an HTTP status line")]
    MalformedStatus,
    /// The response status is outside 200 to 399.
    #[error("HTTP status {0} is outside 200-399")]
    Status(u16),
    /// Copying the helper into the install directory failed.
    #[error("cannot install into {}: {source}", .dir.display())]
    Install { dir: PathBuf, source: io::Error },
}

/// URL scheme of an HTTP probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Scheme {
    #[value(name = "HTTP")]
    Http,
    #[value(name = "HTTPS")]
    Https,
}

#[derive(Debug, Parser)]
#[command(
    name = "odp-probe",
    version,
    about = "Kubelet-equivalent probes against 127.0.0.1"
)]
#[command(subcommand_required = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Sends a kubelet-style HTTP GET and succeeds on a status from 200 to 399.
    HttpGet(HttpGetArgs),
    /// Succeeds when a TCP connection to 127.0.0.1 opens.
    Tcp {
        /// Port on 127.0.0.1 to connect to.
        #[arg(long)]
        port: u16,
    },
    /// Copies this executable to `<dir>/odp-probe` with mode 0555.
    Install {
        /// Directory to install the helper into.
        dir: PathBuf,
    },
}

#[derive(Debug, Args)]
struct HttpGetArgs {
    /// Port on 127.0.0.1 to probe.
    #[arg(long)]
    port: u16,
    /// Request path.
    #[arg(long, default_value = "/", value_parser = require_plain)]
    path: String,
    /// URL scheme; HTTPS skips certificate verification as kubelet does.
    #[arg(long, value_enum, default_value_t = Scheme::Http)]
    scheme: Scheme,
    /// Host header and TLS server name; defaults to 127.0.0.1 with the probe port.
    #[arg(long, value_parser = require_plain)]
    host: Option<String>,
    /// Extra request header as NAME:VALUE; Host, User-Agent and Accept replace their defaults.
    #[arg(long = "header", value_name = "NAME:VALUE", value_parser = parse_header)]
    headers: Vec<(String, String)>,
}

/// Runs the probe CLI with `args`, returning 0 on success, 1 on probe or install failure, and
/// clap's usage status (2) for bad arguments.
pub fn run<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let status = if error.use_stderr() {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            };
            return match error.print() {
                Ok(()) => status,
                Err(_) => ExitCode::FAILURE,
            };
        }
    };
    let result = match cli.command {
        Command::HttpGet(args) => http_get(&args),
        Command::Tcp { port } => connect(port).map(drop),
        Command::Install { dir } => install(&dir),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("odp-probe: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Sends the kubelet-style request to `127.0.0.1:port` and checks the status it returns.
fn http_get(args: &HttpGetArgs) -> Result<(), ProbeError> {
    let host = args
        .host
        .clone()
        .unwrap_or_else(|| format!("127.0.0.1:{}", args.port));
    let request = request_head(&args.path, &host, &args.headers);
    let tcp = connect(args.port)?;
    let status = match args.scheme {
        Scheme::Http => exchange(tcp, &request)?,
        Scheme::Https => exchange(tls_stream(tcp, &host)?, &request)?,
    };
    match status {
        200..=399 => Ok(()),
        code => Err(ProbeError::Status(code)),
    }
}

/// Opens a TCP connection to `127.0.0.1:port`.
fn connect(port: u16) -> Result<TcpStream, ProbeError> {
    TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .map_err(|source| ProbeError::Connect { port, source })
}

/// Writes `request`, then returns the status code from the response's first line.
fn exchange(mut stream: impl Read + Write, request: &str) -> Result<u16, ProbeError> {
    stream.write_all(request.as_bytes())?;
    stream.flush()?;
    let mut status_line = String::new();
    BufReader::new(stream).read_line(&mut status_line)?;
    parse_status(&status_line).ok_or(ProbeError::MalformedStatus)
}

/// Wraps `tcp` in a TLS client session named by `host` when it parses as a DNS name or an IP
/// address, and by the loopback address otherwise. Only a DNS name is sent as SNI. The
/// certificate is not verified.
fn tls_stream(tcp: TcpStream, host: &str) -> io::Result<StreamOwned<ClientConnection, TcpStream>> {
    let name = ServerName::try_from(host_without_port(host).to_owned())
        .unwrap_or_else(|_| ServerName::from(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let connection = ClientConnection::new(tls_config().map_err(io::Error::other)?, name)
        .map_err(io::Error::other)?;
    Ok(StreamOwned::new(connection, tcp))
}

/// Client configuration using the aws-lc-rs provider and no certificate verification.
fn tls_config() -> Result<Arc<ClientConfig>, rustls::Error> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipCertificateVerification { provider }))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Accepts any server certificate, as kubelet's HTTPS probes do. Handshake signatures are
/// still checked against the certificate the server presents.
#[derive(Debug)]
struct SkipCertificateVerification {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for SkipCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Copies the running executable to `<dir>/odp-probe` with mode 0555.
fn install(dir: &Path) -> Result<(), ProbeError> {
    let destination = dir.join(HELPER_NAME);
    let copied = std::env::current_exe()
        .and_then(|source| fs::copy(source, &destination))
        .and_then(|_| fs::set_permissions(&destination, fs::Permissions::from_mode(0o555)));
    copied.map_err(|source| ProbeError::Install {
        dir: dir.to_path_buf(),
        source,
    })
}

/// Builds the request head. Host, User-Agent and Accept are omitted when a `--header` of the
/// same name replaces them; Connection is always sent; the caller's headers come last.
fn request_head(path: &str, host: &str, headers: &[(String, String)]) -> String {
    let overridden = |name: &str| {
        headers
            .iter()
            .any(|(given, _)| given.eq_ignore_ascii_case(name))
    };
    let mut lines = vec![format!("GET {path} HTTP/1.1")];
    if !overridden("Host") {
        lines.push(format!("Host: {host}"));
    }
    if !overridden("User-Agent") {
        lines.push(format!("User-Agent: {KUBE_USER_AGENT}"));
    }
    if !overridden("Accept") {
        lines.push("Accept: */*".to_owned());
    }
    lines.push("Connection: close".to_owned());
    lines.extend(
        headers
            .iter()
            .map(|(name, value)| format!("{name}: {value}")),
    );
    let mut head = lines.join("\r\n");
    head.push_str("\r\n\r\n");
    head
}

/// Parses a `NAME:VALUE` header, splitting at the first colon and trimming the value.
fn parse_header(raw: &str) -> Result<(String, String), ProbeError> {
    let (name, value) = raw
        .split_once(':')
        .ok_or_else(|| ProbeError::Invalid(format!("header {raw:?} must be NAME:VALUE")))?;
    if name.is_empty() || !name.bytes().all(is_token_byte) {
        return Err(ProbeError::Invalid(format!(
            "header name {name:?} is not a valid token"
        )));
    }
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(ProbeError::Invalid(format!(
            "header {name} has a control character in its value"
        )));
    }
    Ok((name.to_owned(), value.trim().to_owned()))
}

/// Whether `byte` may appear in an HTTP header name (RFC 9110 token characters).
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// Accepts a non-empty run of printable ASCII without spaces, so the value can sit in a
/// request line or a Host header unchanged.
fn require_plain(value: &str) -> Result<String, ProbeError> {
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_graphic()) {
        Ok(value.to_owned())
    } else {
        Err(ProbeError::Invalid(format!(
            "{value:?} must be printable ASCII without spaces"
        )))
    }
}

/// Reads the status code from an HTTP status line.
fn parse_status(line: &str) -> Option<u16> {
    let mut fields = line.split_ascii_whitespace();
    let version = fields.next()?;
    let code = fields.next()?;
    let well_formed = version.starts_with("HTTP/")
        && code.len() == 3
        && code.bytes().all(|byte| byte.is_ascii_digit());
    if well_formed { code.parse().ok() } else { None }
}

/// Strips the port from `host`, unbracketing IPv6 literals. A bare IPv6 address has no port.
fn host_without_port(host: &str) -> &str {
    if let Some(bracketed) = host.strip_prefix('[') {
        return bracketed
            .split_once(']')
            .map_or(bracketed, |(address, _)| address);
    }
    match host.split_once(':') {
        Some((name, port)) if !port.contains(':') => name,
        _ => host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{Ipv4Addr, TcpListener};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ServerConfig, ServerConnection, StreamOwned};

    const OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    static TLS12_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];
    /// How long a test server waits for the probe before failing the test.
    const SERVER_DEADLINE: Duration = Duration::from_secs(5);

    /// Runs the probe CLI with `args` after the program name.
    fn probe(args: &[&str]) -> ExitCode {
        run(std::iter::once("odp-probe").chain(args.iter().copied()))
    }

    /// Accepts one probe connection. Panics after `SERVER_DEADLINE` so a probe that never
    /// connects fails the test instead of blocking it.
    fn accept_one(listener: &TcpListener) -> TcpStream {
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let deadline = Instant::now() + SERVER_DEADLINE;
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("no probe connection: {error}"),
            }
        };
        stream.set_nonblocking(false).expect("blocking stream");
        stream
            .set_read_timeout(Some(SERVER_DEADLINE))
            .expect("read timeout");
        stream
    }

    /// Reads a request head up to and including its blank line, or to end of stream.
    fn read_head(stream: impl Read) -> String {
        let mut reader = BufReader::new(stream);
        let mut head = String::new();
        let mut line = String::new();
        loop {
            line.clear();
            let read = reader.read_line(&mut line).expect("read request");
            head.push_str(&line);
            if read == 0 || line == "\r\n" {
                return head;
            }
        }
    }

    /// Serves one plaintext request with `response` and returns the request head it read.
    fn serve_once(response: &'static str) -> (u16, JoinHandle<String>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        let server = thread::spawn(move || {
            let mut stream = accept_one(&listener);
            let head = read_head(&mut stream);
            stream
                .write_all(response.as_bytes())
                .expect("write response");
            head
        });
        (port, server)
    }

    /// Serves one HTTPS request with `response` over a self-signed `localhost` certificate,
    /// negotiating from `versions`. Returns the request head and the SNI name the client sent.
    fn serve_tls_once(
        response: &'static str,
        versions: &'static [&'static rustls::SupportedProtocolVersion],
    ) -> (u16, JoinHandle<(String, Option<String>)>) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("self-signed certificate");
        let cert = certified.cert.der().clone();
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
            certified.signing_key.serialize_der(),
        ));
        let config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(versions)
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server certificate");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        let server = thread::spawn(move || {
            let tcp = accept_one(&listener);
            let connection = ServerConnection::new(Arc::new(config)).expect("server connection");
            let mut tls = StreamOwned::new(connection, tcp);
            let head = read_head(&mut tls);
            tls.write_all(response.as_bytes()).expect("write response");
            let sni = tls.conn.server_name().map(str::to_owned);
            (head, sni)
        });
        (port, server)
    }

    /// Returns a loopback port with nothing listening on it.
    fn closed_port() -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        listener.local_addr().expect("local addr").port()
    }

    /// Creates a fresh scratch directory under the system temporary directory.
    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("odp-probe-{}-{name}", std::process::id()));
        fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    #[test]
    fn odp_probe_http_get_accepts_200() {
        let (port, server) = serve_once(OK);
        assert_eq!(
            probe(&["http-get", "--port", &port.to_string()]),
            ExitCode::SUCCESS
        );
        server.join().expect("server thread");
    }

    #[test]
    fn odp_probe_http_get_accepts_399() {
        let (port, server) =
            serve_once("HTTP/1.1 399 Custom\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        assert_eq!(
            probe(&["http-get", "--port", &port.to_string()]),
            ExitCode::SUCCESS
        );
        server.join().expect("server thread");
    }

    #[test]
    fn odp_probe_http_get_does_not_follow_302_redirects() {
        let (port, server) = serve_once(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(
            probe(&["http-get", "--port", &port.to_string()]),
            ExitCode::SUCCESS
        );
        server.join().expect("server thread");
    }

    #[test]
    fn odp_probe_http_get_fails_on_500() {
        let (port, server) = serve_once(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(
            probe(&["http-get", "--port", &port.to_string()]),
            ExitCode::FAILURE
        );
        server.join().expect("server thread");
    }

    #[test]
    fn odp_probe_http_get_fails_when_connection_refused() {
        let port = closed_port();
        assert_eq!(
            probe(&["http-get", "--port", &port.to_string()]),
            ExitCode::FAILURE
        );
    }

    #[test]
    fn odp_probe_http_get_fails_on_malformed_status_line() {
        for response in [
            "",
            "garbage\r\n\r\n",
            "HTTP/1.1 abc OK\r\nConnection: close\r\n\r\n",
        ] {
            let (port, server) = serve_once(response);
            assert_eq!(
                probe(&["http-get", "--port", &port.to_string()]),
                ExitCode::FAILURE,
                "response {response:?} must fail"
            );
            server.join().expect("server thread");
        }
    }

    #[test]
    fn odp_probe_http_get_sends_kubelet_request_line_and_default_headers() {
        let (port, server) = serve_once(OK);
        assert_eq!(
            probe(&[
                "http-get",
                "--port",
                &port.to_string(),
                "--path",
                "/healthz"
            ]),
            ExitCode::SUCCESS
        );
        let head = server.join().expect("server thread");
        assert_eq!(
            head,
            format!(
                "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUser-Agent: kube-probe/odp-probe\r\nAccept: */*\r\nConnection: close\r\n\r\n"
            )
        );
    }

    #[test]
    fn odp_probe_http_get_host_flag_sets_host_header() {
        let (port, server) = serve_once(OK);
        assert_eq!(
            probe(&[
                "http-get",
                "--port",
                &port.to_string(),
                "--host",
                "example.test"
            ]),
            ExitCode::SUCCESS
        );
        let head = server.join().expect("server thread");
        assert_eq!(
            head,
            "GET / HTTP/1.1\r\nHost: example.test\r\nUser-Agent: kube-probe/odp-probe\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn odp_probe_http_get_header_flags_replace_host_user_agent_and_accept() {
        let (port, server) = serve_once(OK);
        assert_eq!(
            probe(&[
                "http-get",
                "--port",
                &port.to_string(),
                "--header",
                "host: override.test",
                "--header",
                "user-agent: custom",
                "--header",
                "Accept: text/plain",
                "--header",
                "X-Probe: 1",
            ]),
            ExitCode::SUCCESS
        );
        let head = server.join().expect("server thread");
        assert_eq!(
            head,
            "GET / HTTP/1.1\r\nConnection: close\r\nhost: override.test\r\nuser-agent: custom\r\nAccept: text/plain\r\nX-Probe: 1\r\n\r\n"
        );
    }

    #[test]
    fn odp_probe_parse_header_splits_at_first_colon_and_trims() {
        assert_eq!(
            parse_header("X-Probe:  a:b ").expect("valid header"),
            ("X-Probe".to_owned(), "a:b".to_owned())
        );
    }

    #[test]
    fn odp_probe_parse_header_rejects_bad_names_and_line_breaks() {
        for raw in [
            "no-colon",
            ": empty-name",
            "Bad Name: x",
            "X: a\r\nEvil: 1",
            "X: a\nEvil: 1",
        ] {
            assert!(parse_header(raw).is_err(), "{raw:?} must be rejected");
        }
    }

    #[test]
    fn odp_probe_require_plain_rejects_spaces_and_control_characters() {
        assert!(require_plain("/healthz?x=1").is_ok());
        for value in ["/a b", "/a\r\nX: y", "host\n"] {
            assert!(require_plain(value).is_err(), "{value:?} must be rejected");
        }
    }

    #[test]
    fn odp_probe_parse_status_reads_code_from_http_status_line() {
        assert_eq!(parse_status("HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(parse_status("HTTP/1.0 301\r\n"), Some(301));
        assert_eq!(parse_status("HTTP/1.1 20 X\r\n"), None);
        assert_eq!(parse_status("SMTP/1.1 200 OK\r\n"), None);
        assert_eq!(parse_status(""), None);
    }

    #[test]
    fn odp_probe_host_without_port_strips_the_port() {
        assert_eq!(host_without_port("localhost:8080"), "localhost");
        assert_eq!(host_without_port("[::1]:8080"), "::1");
        assert_eq!(host_without_port("::1"), "::1");
        assert_eq!(host_without_port("example.test"), "example.test");
    }

    #[test]
    fn odp_probe_https_accepts_self_signed_certificate() {
        let (port, server) = serve_tls_once(OK, rustls::ALL_VERSIONS);
        assert_eq!(
            probe(&[
                "http-get",
                "--port",
                &port.to_string(),
                "--scheme",
                "HTTPS",
                "--host",
                "localhost",
            ]),
            ExitCode::SUCCESS
        );
        server.join().expect("server thread");
    }

    #[test]
    fn odp_probe_https_accepts_tls12_server() {
        let (port, server) = serve_tls_once(OK, TLS12_ONLY);
        assert_eq!(
            probe(&[
                "http-get",
                "--port",
                &port.to_string(),
                "--scheme",
                "HTTPS",
                "--host",
                "localhost",
            ]),
            ExitCode::SUCCESS
        );
        server.join().expect("server thread");
    }

    #[test]
    fn odp_probe_https_sends_host_without_port_as_sni() {
        let (port, server) = serve_tls_once(OK, rustls::ALL_VERSIONS);
        let host = format!("localhost:{port}");
        assert_eq!(
            probe(&[
                "http-get",
                "--port",
                &port.to_string(),
                "--scheme",
                "HTTPS",
                "--host",
                &host,
            ]),
            ExitCode::SUCCESS
        );
        let (_, sni) = server.join().expect("server thread");
        assert_eq!(sni.as_deref(), Some("localhost"));
    }

    #[test]
    fn odp_probe_https_sends_no_sni_for_default_loopback_host() {
        let (port, server) = serve_tls_once(OK, rustls::ALL_VERSIONS);
        assert_eq!(
            probe(&["http-get", "--port", &port.to_string(), "--scheme", "HTTPS"]),
            ExitCode::SUCCESS
        );
        let (_, sni) = server.join().expect("server thread");
        assert_eq!(sni, None);
    }

    #[test]
    fn odp_probe_https_sends_no_sni_for_host_that_is_not_a_dns_name() {
        let (port, server) = serve_tls_once(OK, rustls::ALL_VERSIONS);
        assert_eq!(
            probe(&[
                "http-get",
                "--port",
                &port.to_string(),
                "--scheme",
                "HTTPS",
                "--host",
                "a..b",
            ]),
            ExitCode::SUCCESS
        );
        let (head, sni) = server.join().expect("server thread");
        assert!(head.contains("\r\nHost: a..b\r\n"), "{head}");
        assert_eq!(sni, None);
    }

    #[test]
    fn odp_probe_https_fails_against_plaintext_server() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        let server = thread::spawn(move || {
            let mut stream = accept_one(&listener);
            stream.write_all(OK.as_bytes()).expect("write response");
        });
        assert_eq!(
            probe(&["http-get", "--port", &port.to_string(), "--scheme", "HTTPS"]),
            ExitCode::FAILURE
        );
        server.join().expect("server thread");
    }

    #[test]
    fn odp_probe_tcp_succeeds_when_port_accepts_connections() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        assert_eq!(
            probe(&["tcp", "--port", &port.to_string()]),
            ExitCode::SUCCESS
        );
    }

    #[test]
    fn odp_probe_tcp_fails_when_connection_refused() {
        let port = closed_port();
        assert_eq!(
            probe(&["tcp", "--port", &port.to_string()]),
            ExitCode::FAILURE
        );
    }

    #[test]
    fn odp_probe_install_copies_executable_with_mode_0555() {
        let dir = scratch_dir("install-copies");
        assert_eq!(
            probe(&["install", dir.to_str().expect("utf-8 path")]),
            ExitCode::SUCCESS
        );
        let installed = fs::metadata(dir.join("odp-probe")).expect("installed helper");
        let source =
            fs::metadata(std::env::current_exe().expect("current exe")).expect("source metadata");
        assert_eq!(installed.len(), source.len());
        assert_eq!(installed.permissions().mode() & 0o777, 0o555);
        fs::remove_dir_all(&dir).expect("remove scratch dir");
    }

    #[test]
    fn odp_probe_install_fails_for_missing_directory() {
        let missing =
            std::env::temp_dir().join(format!("odp-probe-{}-no-such-dir", std::process::id()));
        assert_eq!(
            probe(&["install", missing.to_str().expect("utf-8 path")]),
            ExitCode::FAILURE
        );
        assert!(!missing.exists());
    }

    #[test]
    fn odp_probe_bad_arguments_exit_2() {
        assert_eq!(probe(&[]), ExitCode::from(2));
        assert_eq!(probe(&["bogus"]), ExitCode::from(2));
        assert_eq!(probe(&["http-get"]), ExitCode::from(2));
        assert_eq!(
            probe(&["http-get", "--port", "1", "--scheme", "ftp"]),
            ExitCode::from(2)
        );
    }

    #[test]
    fn odp_probe_help_exits_zero() {
        assert_eq!(probe(&["--help"]), ExitCode::SUCCESS);
    }
}
