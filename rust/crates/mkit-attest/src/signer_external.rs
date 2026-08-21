//! External signer — subprocess-based [`Signer`] impl driven over
//! the mkit-rpc signer protocol (length-prefixed buffa frames on
//! stdin/stdout). See `rust/crates/mkit-rpc/proto/mkit/rpc/v1/signer/signer.proto` and
//! `docs/specs/SPEC-EXTERNAL-SIGNER.md`.
//!
//! Conversation per sign call:
//!
//! ```text
//! parent → child:    Hello{ protocol = v1, want_capabilities = false }
//!                    SignRequest{ algorithm, key_form, key_ref, payload }
//! child  → parent:   HelloResponse{ ... }   (capabilities; we discard)
//!                    SignResponse{ signature, public_key, key_id }
//!                      OR
//!                    Error{ code, message }
//!                      OR (zero or more times, mid-sign)
//!                    PinPrompt{ reason, retries_remaining, wants_pin }
//! parent → child:    PinResponse{ pin }     (sourced from a
//!                                            `PinProvider`, never argv)
//! ```
//!
//! The child's stdin is kept open for the whole conversation (not
//! closed right after the initial write) specifically so a `PinPrompt`
//! mid-sign can be answered on the same pipe; it is closed only once a
//! terminal `SignResponse`/`Error` has been read.
//!
//! `keyid` is only known after the first sign call; `keyid()` before
//! that returns `Error::KeyIdNotKnownUntilFirstSign`.

// `ref_option` flags `&Option<T>` arguments. Wire-frame fields are
// `Option<T>` (Edition 2023 explicit presence); passing references
// through helpers is the natural shape.
#![allow(clippy::ref_option)]

use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use mkit_rpc::mkit::rpc::v1::signer::{
    Hello, PinPrompt, PinResponse, SignRequest, SignResponse, SignerFrame, signer_frame,
};
use mkit_rpc::mkit::rpc::v1::{Algorithm as RpcAlgorithm, KeyForm, ProtocolVersion};
use mkit_rpc::{FrameError, read_frame, write_frame};

use crate::Error;
use crate::algorithm::Algorithm;
use crate::pin_provider::{PinPromptInfo, PinProvider, TtyPinProvider};
use crate::signer::Signer;
#[cfg(feature = "algo-p256")]
use crate::webauthn::WebAuthnPolicy;

/// Cap for child-stderr drain. 1 MiB is generous; stderr is advisory.
const MAX_STDERR_DRAIN: usize = 1024 * 1024;

/// Cap on `PinPrompt` round trips within a single sign conversation.
/// SPEC-EXTERNAL-SIGNER §4 allows a signer to re-prompt (e.g. a wrong
/// PIN with retries remaining), but an unbounded loop would let a
/// malicious or buggy signer spin the host indefinitely inside the
/// same wall-clock deadline. Chosen generously above any real
/// CTAP/TPM/PKCS#11 retry counter (typically well under 8 attempts
/// before a hardware lockout).
const MAX_PIN_PROMPTS: u32 = 8;

/// Default wall-clock budget for the entire signer conversation
/// (spawn → request-write → response-read → stderr-drain → child-exit).
///
/// Deliberately generous: hardware-backed signers (`YubiKey`, secure
/// enclave, smartcard) routinely block on a physical touch, a PIN entry,
/// or a biometric prompt before they emit a single byte of stdout. A
/// tight default would make those signers unusable. Callers that drive
/// only software signers can tighten this via [`ExternalSigner::with_timeout`]
/// (or the `attest.external_signer_timeout_secs` config key).
// 120 seconds = 2 minutes; written in seconds because `Duration::from_mins`
// is not const-stable on the pinned toolchain.
#[allow(clippy::duration_suboptimal_units)]
pub const DEFAULT_EXTERNAL_SIGNER_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug)]
pub struct ExternalSigner {
    binary_path: PathBuf,
    cached_keyid: Option<String>,
    algorithm: Algorithm,
    args: Vec<String>,
    /// Single wall-clock budget covering the whole sign conversation.
    /// On expiry the child is killed and reaped and an
    /// [`Error::ExternalSignerTimeout`] (phase-named) is returned.
    timeout: Duration,
    /// Ceremony policy applied when the signer returns a `WebAuthn`
    /// assertion. Defaults to [`WebAuthnPolicy::permissive`].
    #[cfg(feature = "algo-p256")]
    webauthn_policy: WebAuthnPolicy,
    /// Sources a PIN when the signer emits a `PinPrompt` mid-sign.
    /// Defaults to [`TtyPinProvider`] (interactive terminal prompt;
    /// never argv or an environment variable — SPEC-EXTERNAL-SIGNER
    /// §2, THREAT-MODEL §3.2).
    pin_provider: Box<dyn PinProvider>,
}

impl ExternalSigner {
    /// Construct an external signer wrapping `binary_path`.
    ///
    /// The path MUST be absolute. A relative path is rejected with
    /// [`Error::ExternalSignerRelativePath`]: at spawn time, a relative
    /// path would resolve against the current `PATH` (or CWD on
    /// Windows) and pick up a same-named binary planted by an attacker
    /// earlier in the search order. Forcing absolute paths at
    /// construction closes that TOCTOU hole.
    ///
    /// # Errors
    /// [`Error::ExternalSignerRelativePath`] if `binary_path` is not
    /// absolute.
    pub fn new(binary_path: impl Into<PathBuf>) -> Result<Self, Error> {
        Self::with_algorithm(binary_path, Algorithm::Ed25519)
    }

    /// Like [`Self::new`] but records a caller-asserted algorithm.
    ///
    /// # Errors
    /// See [`Self::new`].
    pub fn with_algorithm(
        binary_path: impl Into<PathBuf>,
        algorithm: Algorithm,
    ) -> Result<Self, Error> {
        let binary_path = binary_path.into();
        if !binary_path.is_absolute() {
            return Err(Error::ExternalSignerRelativePath(
                binary_path.display().to_string(),
            ));
        }
        Ok(Self {
            binary_path,
            cached_keyid: None,
            algorithm,
            args: Vec::new(),
            timeout: DEFAULT_EXTERNAL_SIGNER_TIMEOUT,
            #[cfg(feature = "algo-p256")]
            webauthn_policy: WebAuthnPolicy::permissive(),
            pin_provider: Box::new(TtyPinProvider),
        })
    }

    /// Attach extra argv tokens to be passed verbatim to the child
    /// process on every sign call. Each element is one argv entry —
    /// no shell interpolation. Calling this replaces any previously-set
    /// args.
    #[must_use]
    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Override the wall-clock budget for the whole sign conversation.
    /// See [`DEFAULT_EXTERNAL_SIGNER_TIMEOUT`] for the rationale behind
    /// the generous default. A zero duration is treated as "deadline
    /// already passed" and will time out at the first blocking step,
    /// which is the intended behaviour for a hard kill-switch.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Override the [`WebAuthnPolicy`] applied to `WebAuthn` assertions
    /// returned by the signer. The default is
    /// [`WebAuthnPolicy::permissive`].
    #[cfg(feature = "algo-p256")]
    #[must_use]
    pub fn with_webauthn_policy(mut self, policy: WebAuthnPolicy) -> Self {
        self.webauthn_policy = policy;
        self
    }

    /// Override the [`PinProvider`] used to answer a signer's
    /// `PinPrompt` mid-sign. Defaults to [`TtyPinProvider`]. Callers
    /// embedding `ExternalSigner` in a non-interactive context (a
    /// daemon, a test) MUST supply their own rather than relying on
    /// the interactive default.
    #[must_use]
    pub fn with_pin_provider(mut self, provider: impl PinProvider + 'static) -> Self {
        self.pin_provider = Box::new(provider);
        self
    }
}

impl Signer for ExternalSigner {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    fn keyid(&self) -> Result<String, Error> {
        self.cached_keyid
            .clone()
            .ok_or(Error::KeyIdNotKnownUntilFirstSign)
    }

    fn sign(&mut self, pae: &[u8]) -> Result<Vec<u8>, Error> {
        // Single wall-clock budget for the entire conversation. Every
        // blocking step in `run_conversation` is measured against this
        // one deadline, so a signer that is slow across several phases
        // still cannot exceed the total budget.
        let deadline = Instant::now() + self.timeout;

        let child = Command::new(&self.binary_path)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::ExternalSignerSpawn(e.to_string()))?;

        let (signature, key_id) = self.run_conversation(child, pae, deadline)?;
        self.cached_keyid = Some(key_id);
        Ok(signature)
    }
}

impl ExternalSigner {
    /// Drive the bounded sign conversation against an already-spawned
    /// child: concurrent stderr drain, bounded request-write, bounded
    /// response-read, bounded stderr-drain join, bounded child-exit. On
    /// ANY error the child is killed+reaped and the stderr drain joined
    /// (via [`Conversation::fail`]) before returning, so there is never
    /// a leaked child or thread.
    fn run_conversation(
        &self,
        mut child: Child,
        pae: &[u8],
        deadline: Instant,
    ) -> Result<(Vec<u8>, String), Error> {
        // --- Concurrent stderr drain (the deadlock fix) ------------
        //
        // Spawn the stderr drain IMMEDIATELY, before we write the
        // request or read any stdout: if the child floods stderr before
        // emitting stdout and nobody drains it, the child blocks on a
        // full stderr pipe while we block reading stdout — a two-pipe
        // deadlock. The drain thread reads to EOF unconditionally,
        // capturing only a bounded prefix but never ceasing to discard.
        let Some(stderr) = child.stderr.take() else {
            terminate_child_now(&mut child);
            return Err(Error::ExternalSignerSpawn("stderr not piped".into()));
        };
        let stderr_join = spawn_stderr_drainer(stderr);
        let mut conv = Conversation {
            child,
            stderr_join: Some(stderr_join),
        };

        // --- Write the request (Hello + SignRequest) --------------
        //
        // Fired together so the signer can pipeline. The write runs on
        // its own thread so a child that never reads stdin (while its
        // stdout pipe fills) cannot wedge us past the deadline.
        let hello = SignerFrame {
            body: Some(signer_frame::Body::Hello(Box::new(
                Hello::default()
                    .with_protocol(ProtocolVersion::ProtocolVersion1)
                    .with_caller_id(format!("mkit-attest/{}", env!("CARGO_PKG_VERSION")))
                    .with_want_capabilities(false),
            ))),
            ..Default::default()
        };
        let sign_req = SignerFrame {
            body: Some(signer_frame::Body::SignRequest(Box::new(
                SignRequest::default()
                    .with_algorithm(rpc_algorithm_for(self.algorithm))
                    .with_key_form(rpc_key_form_for(self.algorithm))
                    .with_key_ref(Vec::new())
                    .with_payload(pae.to_vec())
                    .with_context(Vec::new()),
            ))),
            ..Default::default()
        };

        let Some(stdin) = conv.child.stdin.take() else {
            return Err(conv.fail(Error::ExternalSignerSpawn("stdin not piped".into())));
        };
        let write_rx = spawn_request_writer(stdin, hello, sign_req);
        let mut stdin = match recv_until_deadline(&write_rx, deadline) {
            Ok(Ok(stdin)) => stdin,
            Ok(Err(e)) => return Err(conv.fail(e)),
            Err(()) => return Err(conv.fail(Error::ExternalSignerTimeout("request-write"))),
        };

        // --- Read the response (bounded) --------------------------
        let Some(stdout) = conv.child.stdout.take() else {
            return Err(conv.fail(Error::ExternalSignerSpawn("stdout not piped".into())));
        };
        let stdout_rx = spawn_stdout_reader(stdout);

        // SPEC-EXTERNAL-SIGNER §4 / SPEC-RPC §4: the version handshake
        // MUST complete (a HelloResponse) before any other request is
        // processed. A signer that pipelines straight to SignResponse
        // or Error, skipping HelloResponse, is non-conforming — fail
        // closed rather than silently tolerating it, so a signer that
        // never negotiated a protocol version can't slip a response
        // through unnoticed.
        let hello_resp = match recv_frame_until_deadline(&stdout_rx, deadline) {
            Ok(frame) => frame,
            Err(FrameTimeout::Timeout) => {
                return Err(conv.fail(Error::ExternalSignerTimeout("response-read")));
            }
            Err(FrameTimeout::Frame(e)) => return Err(conv.fail(e)),
        };
        if let Err(e) = require_hello_response(&hello_resp) {
            return Err(conv.fail(e));
        }

        // --- Read until a terminal frame, answering PinPrompt -----
        //
        // SPEC-EXTERNAL-SIGNER §4: the signer MAY interleave zero or
        // more PinPrompt frames before its terminal SignResponse /
        // Error. `read_until_terminal_frame` answers each on the spot
        // via `self.pin_provider` and a PinResponse written back on
        // `stdin` (kept open for exactly this reason — see
        // `spawn_request_writer`).
        let resp = self.read_until_terminal_frame(&stdout_rx, &mut stdin, deadline, &mut conv)?;
        // The terminal frame is in hand; no more requests are coming
        // on this connection. Close stdin now so a signer that loops
        // on stdin (SPEC-EXTERNAL-SIGNER §8) sees EOF and can exit —
        // this must happen AFTER the PinPrompt loop above, which needs
        // stdin to stay open for PinResponse writes.
        drop(stdin);

        let (signature, key_id) = match self.extract_signature_with_policy(resp, pae) {
            Ok(v) => v,
            Err(e) => return Err(conv.fail(e)),
        };

        // --- Drain stderr to completion (bounded) -----------------
        //
        // Join the drain thread to collect the captured prefix. It
        // reaches EOF once the child closes stderr — on (or just before)
        // exit. `take()` hands ownership out of the guard so the guard's
        // Drop won't double-join.
        let stderr_join = conv.stderr_join.take().expect("stderr_join present");
        let stderr_bytes = match join_until_deadline(stderr_join, deadline) {
            Some(Ok(bytes)) => bytes,
            // A panicked drain thread just yields empty diagnostics.
            Some(Err(())) => Vec::new(),
            None => return Err(conv.fail(Error::ExternalSignerTimeout("stderr-drain"))),
        };

        // --- Wait for child exit (bounded) ------------------------
        //
        // Reap even with a valid response in hand: avoids a zombie and
        // honours the exit status. A signer that writes a valid response
        // then never exits is bounded here.
        if wait_child_until_deadline(&mut conv.child, deadline).is_none() {
            return Err(conv.fail(Error::ExternalSignerTimeout("child-exit")));
        }
        // A missing status here means the child was already reaped (or a
        // benign race): we have a verified response and the child is no
        // longer alive, so treat it as success.
        let Ok(Some(status)) = conv.child.try_wait() else {
            return Ok((signature, key_id));
        };
        if !status.success() {
            // A non-zero exit means the signer didn't trust its own
            // output even though we got a response frame — surface its
            // stderr to the caller.
            let msg = String::from_utf8_lossy(&stderr_bytes).into_owned();
            return Err(Error::ExternalSignerFailed(msg));
        }

        Ok((signature, key_id))
    }

    /// Validate + extract the signature from a response frame, applying
    /// this signer's configured [`WebAuthnPolicy`] on the `WebAuthn` path.
    fn extract_signature_with_policy(
        &self,
        frame: SignerFrame,
        pae: &[u8],
    ) -> Result<(Vec<u8>, String), Error> {
        #[cfg(feature = "algo-p256")]
        {
            extract_signature(frame, self.algorithm, pae, &self.webauthn_policy)
        }
        #[cfg(not(feature = "algo-p256"))]
        {
            extract_signature(frame, self.algorithm, pae)
        }
    }

    /// Read frames off `stdout_rx` until a terminal `SignResponse`/
    /// `Error`, answering any `PinPrompt` along the way via
    /// `self.pin_provider` and writing the `PinResponse` back on
    /// `stdin`. The round-trip count is capped at [`MAX_PIN_PROMPTS`]
    /// so a malicious or buggy signer can't spin the host forever
    /// inside one wall-clock deadline. Any failure tears the
    /// conversation down via `conv.fail` before returning, matching
    /// every other error path in [`Self::run_conversation`].
    fn read_until_terminal_frame(
        &self,
        stdout_rx: &mpsc::Receiver<Result<SignerFrame, FrameError>>,
        stdin: &mut std::process::ChildStdin,
        deadline: Instant,
        conv: &mut Conversation,
    ) -> Result<SignerFrame, Error> {
        let mut pin_prompts_seen: u32 = 0;
        loop {
            let frame = match recv_frame_until_deadline(stdout_rx, deadline) {
                Ok(frame) => frame,
                Err(FrameTimeout::Timeout) => {
                    return Err(conv.fail(Error::ExternalSignerTimeout("response-read")));
                }
                Err(FrameTimeout::Frame(e)) => return Err(conv.fail(e)),
            };
            let Some(signer_frame::Body::PinPrompt(ref prompt)) = frame.body else {
                return Ok(frame);
            };
            pin_prompts_seen += 1;
            if pin_prompts_seen > MAX_PIN_PROMPTS {
                return Err(conv.fail(Error::ExternalSignerBadResponse(format!(
                    "signer sent more than {MAX_PIN_PROMPTS} PinPrompt frames in one conversation"
                ))));
            }
            let pin = match self.pin_provider.provide_pin(&pin_prompt_info(prompt)) {
                Ok(pin) => pin,
                Err(e) => return Err(conv.fail(e)),
            };
            if let Err(e) = write_frame(stdin, &pin_response_frame(pin)) {
                return Err(conv.fail(Error::ExternalSignerSpawn(format!(
                    "write pin response: {e}"
                ))));
            }
        }
    }
}

// ---------------------------------------------------------------------
// Bounded-execution helpers (mirrors mkit-transport-ssh's reader/timeout
// pattern; intentionally no async runtime in mkit-attest).
// ---------------------------------------------------------------------

/// Owns the child + its stderr-drain thread for the duration of a sign
/// conversation. Centralises teardown so every error path kills+reaps
/// the child and joins the drain thread exactly once. The `Drop` impl is
/// a safety net for any path that forgets to call [`Conversation::fail`]
/// (e.g. a future panic-unwind): it kills the child and joins the drain.
struct Conversation {
    child: Child,
    stderr_join: Option<thread::JoinHandle<Vec<u8>>>,
}

/// Grace period for joining the stderr-drain thread on a teardown path
/// before detaching it. The thread only ends when its stderr pipe
/// reaches EOF; after we SIGKILL the direct child a *grandchild* may
/// still hold the inherited stderr write-end open (e.g. a reparented
/// `sleep`), so an unconditional join could block until that grandchild
/// exits — which on a hung signer is never. We therefore wait only
/// briefly (the kill usually closes the pipe immediately) and then
/// detach: the thread holds nothing but a pipe fd and a bounded `Vec`,
/// so dropping its handle leaks no meaningful resource and the thread
/// exits at the latest when the process does.
const STDERR_JOIN_GRACE: Duration = Duration::from_millis(200);

impl Conversation {
    /// Tear down on the error path: kill+reap the child, then join the
    /// drain thread within [`STDERR_JOIN_GRACE`] (detaching it if a
    /// surviving grandchild still holds the stderr pipe open), then hand
    /// the error straight back.
    fn fail(&mut self, err: Error) -> Error {
        terminate_child_now(&mut self.child);
        if let Some(join) = self.stderr_join.take() {
            detach_join_with_grace(join);
        }
        err
    }
}

impl Drop for Conversation {
    fn drop(&mut self) {
        // Best-effort: the happy path and `fail` have normally already
        // reaped/joined, so these are no-ops. This only fires if a path
        // returned without going through `fail`.
        terminate_child_now(&mut self.child);
        if let Some(join) = self.stderr_join.take() {
            detach_join_with_grace(join);
        }
    }
}

/// Join a stderr-drain thread but never block past [`STDERR_JOIN_GRACE`].
/// If the thread is still reading at the deadline (its pipe held open by
/// a reparented grandchild), the handle is simply dropped — the thread
/// is detached and will exit when the pipe finally closes or the process
/// ends.
fn detach_join_with_grace(handle: thread::JoinHandle<Vec<u8>>) {
    let deadline = Instant::now() + STDERR_JOIN_GRACE;
    loop {
        if handle.is_finished() {
            let _ = handle.join();
            return;
        }
        if Instant::now() >= deadline {
            // Detach: drop the handle without joining.
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

/// Spawn a thread that drains the child's stderr to EOF, capturing only
/// a diagnostic prefix (capped at [`MAX_STDERR_DRAIN`]) but NEVER
/// stopping reading. Returns a join handle yielding the captured prefix.
fn spawn_stderr_drainer<R: Read + Send + 'static>(mut r: R) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut out = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match r.read(&mut chunk) {
                // EOF (0) or a read error both end the drain.
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    // Keep draining unconditionally so the child's
                    // stderr pipe never fills; only the captured prefix
                    // is bounded.
                    if out.len() < MAX_STDERR_DRAIN {
                        let room = MAX_STDERR_DRAIN - out.len();
                        out.extend_from_slice(&chunk[..n.min(room)]);
                    }
                }
            }
        }
        out
    })
}

/// Spawn a thread that writes the Hello + `SignRequest` frames to the
/// child's stdin. On success, hands `stdin` back over the channel
/// instead of closing it: the caller keeps it open for the rest of the
/// conversation so a mid-sign `PinPrompt` can be answered with a
/// `PinResponse` on the same pipe, and closes it only once a terminal
/// `SignResponse`/`Error` has been read (signalling "no more requests"
/// per SPEC-EXTERNAL-SIGNER §8's "loop until EOF" contract). On
/// failure `stdin` is simply dropped when this closure returns,
/// closing the pipe — harmless because the caller kills the child on
/// any write error anyway.
fn spawn_request_writer(
    mut stdin: std::process::ChildStdin,
    hello: SignerFrame,
    sign_req: SignerFrame,
) -> mpsc::Receiver<Result<std::process::ChildStdin, Error>> {
    let (tx, rx) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = (|| {
            write_frame(&mut stdin, &hello)
                .map_err(|e| Error::ExternalSignerSpawn(format!("write hello: {e}")))?;
            write_frame(&mut stdin, &sign_req)
                .map_err(|e| Error::ExternalSignerSpawn(format!("write sign request: {e}")))?;
            Ok(stdin)
        })();
        let _ = tx.send(result);
    });
    rx
}

/// Spawn a thread that reads `SignerFrame`s from the child's stdout and
/// forwards each over a channel. Mirrors the SSH transport's
/// `spawn_stdout_reader`.
fn spawn_stdout_reader(
    mut stdout: std::process::ChildStdout,
) -> mpsc::Receiver<Result<SignerFrame, FrameError>> {
    let (tx, rx) = mpsc::sync_channel(1);
    thread::spawn(move || {
        loop {
            let frame = read_frame::<_, SignerFrame>(&mut stdout);
            let should_stop = frame.is_err();
            if tx.send(frame).is_err() || should_stop {
                break;
            }
        }
    });
    rx
}

/// A `SignerFrame` read that either timed out or surfaced a typed error.
enum FrameTimeout {
    Timeout,
    Frame(Error),
}

/// Block on `rx` until the deadline, mapping a `FrameError` through
/// [`map_frame_error`].
fn recv_frame_until_deadline(
    rx: &mpsc::Receiver<Result<SignerFrame, FrameError>>,
    deadline: Instant,
) -> Result<SignerFrame, FrameTimeout> {
    match recv_until_deadline(rx, deadline) {
        Ok(Ok(frame)) => Ok(frame),
        Ok(Err(e)) => Err(FrameTimeout::Frame(map_frame_error(e))),
        Err(()) => Err(FrameTimeout::Timeout),
    }
}

/// Receive a single value from `rx`, bounded by `deadline`. Returns
/// `Err(())` on timeout or on the sender hanging up (a hung-up sender
/// before any value is treated as a timeout because the child died
/// without producing the expected frame).
fn recv_until_deadline<T>(rx: &mpsc::Receiver<T>, deadline: Instant) -> Result<T, ()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    match rx.recv_timeout(remaining) {
        Ok(v) => Ok(v),
        Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => Err(()),
    }
}

/// Join a stderr-drain thread, bounded by `deadline`. Returns
/// `Some(Ok(bytes))` on a clean join, `Some(Err(()))` on a panicked
/// thread, and `None` on timeout (the thread is still blocked reading).
fn join_until_deadline(
    handle: thread::JoinHandle<Vec<u8>>,
    deadline: Instant,
) -> Option<Result<Vec<u8>, ()>> {
    loop {
        if handle.is_finished() {
            return Some(handle.join().map_err(|_| ()));
        }
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        thread::sleep(core::cmp::min(
            Duration::from_millis(10),
            deadline.saturating_duration_since(now),
        ));
    }
}

/// Poll `child.try_wait()` until it exits or the deadline passes.
/// Returns `Some(())` if the child exited within budget, `None` on
/// timeout (caller is expected to kill+reap).
fn wait_child_until_deadline(child: &mut Child, deadline: Instant) -> Option<()> {
    loop {
        match child.try_wait() {
            // Exited (Some) or un-waitable (Err, e.g. already reaped):
            // either way the child is no longer running, so stop polling.
            Ok(Some(_)) | Err(_) => return Some(()),
            Ok(None) => {}
        }
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        thread::sleep(core::cmp::min(
            Duration::from_millis(10),
            deadline.saturating_duration_since(now),
        ));
    }
}

/// Kill and reap the child unconditionally. Both calls are best-effort:
/// on a child that already exited they are harmless no-ops.
fn terminate_child_now(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Map a `FrameError` from the stdout reader to the crate's error type,
/// preserving the diagnostic distinctions `read_frame_or_err` made.
fn map_frame_error(e: FrameError) -> Error {
    match e {
        FrameError::LengthTruncated => {
            Error::ExternalSignerBadResponse("child closed stdout before sending a frame".into())
        }
        FrameError::LengthTooLarge(n) => {
            Error::ExternalSignerBadResponse(format!("frame length {n} exceeds 1 MiB cap"))
        }
        FrameError::BodyTruncated { expected, .. } => Error::ExternalSignerBadResponse(format!(
            "frame body truncated (expected {expected} bytes)"
        )),
        FrameError::DecodeFailed => {
            Error::ExternalSignerBadResponse("frame failed to decode as SignerFrame".into())
        }
        FrameError::Io(e) => Error::ExternalSignerSpawn(format!("read frame: {e}")),
    }
}

fn rpc_algorithm_for(a: Algorithm) -> RpcAlgorithm {
    match a {
        Algorithm::Ed25519 => RpcAlgorithm::Ed25519,
        Algorithm::Secp256k1 => RpcAlgorithm::Secp256k1,
        Algorithm::P256 => RpcAlgorithm::P256,
        // External-signer dispatch for BLS threshold isn't wired
        // yet — the threshold holder runs in-process. But the proto
        // wire integer is reserved so a future external signer can
        // claim ALGORITHM_BLS12381_THRESHOLD and the mapping
        // already exists.
        #[cfg(feature = "bls-threshold")]
        Algorithm::Bls12381Threshold => RpcAlgorithm::Bls12381Threshold,
    }
}

fn rpc_key_form_for(_a: Algorithm) -> KeyForm {
    // Default to RAW_BYTES — the file signer reads from disk; hardware
    // signers will populate `key_ref` with their own opaque handle and
    // ignore the form anyway.
    KeyForm::RawBytes
}

#[cfg(feature = "algo-p256")]
fn extract_signature(
    frame: SignerFrame,
    expected_algorithm: Algorithm,
    pae: &[u8],
    webauthn_policy: &WebAuthnPolicy,
) -> Result<(Vec<u8>, String), Error> {
    match frame.body {
        Some(signer_frame::Body::SignResponse(sr)) => {
            let signature = sr.signature.clone().ok_or_else(|| {
                Error::ExternalSignerBadResponse("SignResponse missing signature".into())
            })?;
            let key_id = sr.key_id.clone().ok_or_else(|| {
                Error::ExternalSignerBadResponse("SignResponse missing key_id".into())
            })?;
            validate_sign_response_with_policy(
                &sr,
                expected_algorithm,
                pae,
                &signature,
                &key_id,
                webauthn_policy,
            )?;
            Ok((signature, key_id))
        }
        Some(signer_frame::Body::Error(e)) => {
            let msg = e.message.unwrap_or_default();
            Err(Error::ExternalSignerFailed(msg))
        }
        other => Err(Error::ExternalSignerBadResponse(format!(
            "expected SignResponse or Error, got {}",
            frame_name(&other),
        ))),
    }
}

#[cfg(not(feature = "algo-p256"))]
fn extract_signature(
    frame: SignerFrame,
    expected_algorithm: Algorithm,
    pae: &[u8],
) -> Result<(Vec<u8>, String), Error> {
    match frame.body {
        Some(signer_frame::Body::SignResponse(sr)) => {
            let signature = sr.signature.clone().ok_or_else(|| {
                Error::ExternalSignerBadResponse("SignResponse missing signature".into())
            })?;
            let key_id = sr.key_id.clone().ok_or_else(|| {
                Error::ExternalSignerBadResponse("SignResponse missing key_id".into())
            })?;
            validate_sign_response_inner(&sr, expected_algorithm, pae, &signature, &key_id)?;
            Ok((signature, key_id))
        }
        Some(signer_frame::Body::Error(e)) => {
            let msg = e.message.unwrap_or_default();
            Err(Error::ExternalSignerFailed(msg))
        }
        other => Err(Error::ExternalSignerBadResponse(format!(
            "expected SignResponse or Error, got {}",
            frame_name(&other),
        ))),
    }
}

/// Self-consistency check with the permissive `WebAuthn` policy. Stable
/// 5-arg entry point used by tests; the production sign path uses
/// [`validate_sign_response_with_policy`] with the signer's configured
/// policy (p256 builds) or [`validate_sign_response_inner`] (no-p256).
#[cfg(test)]
fn validate_sign_response(
    sr: &SignResponse,
    expected_algorithm: Algorithm,
    pae: &[u8],
    signature: &[u8],
    key_id: &str,
) -> Result<(), Error> {
    #[cfg(feature = "algo-p256")]
    {
        validate_sign_response_with_policy(
            sr,
            expected_algorithm,
            pae,
            signature,
            key_id,
            &WebAuthnPolicy::permissive(),
        )
    }
    #[cfg(not(feature = "algo-p256"))]
    {
        validate_sign_response_inner(sr, expected_algorithm, pae, signature, key_id)
    }
}

/// Self-consistency check, applying `webauthn_policy` on the `WebAuthn`
/// path. Only present when `algo-p256` is enabled (`WebAuthn` requires
/// P-256).
#[cfg(feature = "algo-p256")]
fn validate_sign_response_with_policy(
    sr: &SignResponse,
    expected_algorithm: Algorithm,
    pae: &[u8],
    signature: &[u8],
    key_id: &str,
    webauthn_policy: &WebAuthnPolicy,
) -> Result<(), Error> {
    let actual_algorithm = sr
        .algorithm
        .ok_or_else(|| Error::ExternalSignerBadResponse("SignResponse missing algorithm".into()))?;
    let expected_rpc = rpc_algorithm_for(expected_algorithm);
    if actual_algorithm != expected_rpc {
        return Err(Error::ExternalSignerBadResponse(format!(
            "SignResponse algorithm mismatch: got {}, expected {}",
            actual_algorithm.to_i32(),
            expected_rpc as i32
        )));
    }

    if sr.webauthn.is_set() {
        return validate_webauthn_response(
            sr,
            expected_algorithm,
            pae,
            signature,
            key_id,
            webauthn_policy,
        );
    }

    let public_key = sr.public_key.as_deref().ok_or_else(|| {
        Error::ExternalSignerBadResponse("SignResponse missing public_key".into())
    })?;

    match expected_algorithm {
        Algorithm::Ed25519 => validate_ed25519_response(public_key, pae, signature, key_id),
        Algorithm::Secp256k1 => validate_secp256k1_response(public_key, pae, signature, key_id),
        Algorithm::P256 => validate_p256_response(public_key, pae, signature, key_id),
        // External-signer BLS-threshold dispatch is NOT wired: there is
        // no signature-vs-public-key check for this arm, so accepting it
        // would trust an unverifiable signature returned by the child.
        // Fail closed until external BLS dispatch is actually
        // implemented (see `rpc_algorithm_for`).
        #[cfg(feature = "bls-threshold")]
        Algorithm::Bls12381Threshold => Err(Error::ExternalSignerBadResponse(
            "external BLS-threshold signing is not supported".into(),
        )),
    }
}

/// Self-consistency check for builds without `algo-p256`. A WebAuthn
/// marker is rejected because WebAuthn verification needs P-256.
#[cfg(not(feature = "algo-p256"))]
fn validate_sign_response_inner(
    sr: &SignResponse,
    expected_algorithm: Algorithm,
    pae: &[u8],
    signature: &[u8],
    key_id: &str,
) -> Result<(), Error> {
    let actual_algorithm = sr
        .algorithm
        .ok_or_else(|| Error::ExternalSignerBadResponse("SignResponse missing algorithm".into()))?;
    let expected_rpc = rpc_algorithm_for(expected_algorithm);
    if actual_algorithm != expected_rpc {
        return Err(Error::ExternalSignerBadResponse(format!(
            "SignResponse algorithm mismatch: got {}, expected {}",
            actual_algorithm.to_i32(),
            expected_rpc as i32
        )));
    }

    if sr.webauthn.is_set() {
        return Err(Error::AlgorithmNotEnabled(Algorithm::P256));
    }

    let public_key = sr.public_key.as_deref().ok_or_else(|| {
        Error::ExternalSignerBadResponse("SignResponse missing public_key".into())
    })?;

    match expected_algorithm {
        Algorithm::Ed25519 => validate_ed25519_response(public_key, pae, signature, key_id),
        Algorithm::Secp256k1 => validate_secp256k1_response(public_key, pae, signature, key_id),
        Algorithm::P256 => validate_p256_response(public_key, pae, signature, key_id),
        // External-signer BLS-threshold dispatch is NOT wired: there is
        // no signature-vs-public-key check for this arm, so accepting it
        // would trust an unverifiable signature returned by the child.
        // Fail closed until external BLS dispatch is actually
        // implemented (see `rpc_algorithm_for`).
        #[cfg(feature = "bls-threshold")]
        Algorithm::Bls12381Threshold => Err(Error::ExternalSignerBadResponse(
            "external BLS-threshold signing is not supported".into(),
        )),
    }
}

#[cfg(feature = "algo-p256")]
fn validate_webauthn_response(
    sr: &SignResponse,
    expected_algorithm: Algorithm,
    pae: &[u8],
    signature: &[u8],
    key_id: &str,
    webauthn_policy: &WebAuthnPolicy,
) -> Result<(), Error> {
    if expected_algorithm != Algorithm::P256 {
        return Err(Error::ExternalSignerBadResponse(
            "WebAuthn SignResponse must use P-256".into(),
        ));
    }
    let public_key = sr.public_key.as_deref().ok_or_else(|| {
        Error::ExternalSignerBadResponse("WebAuthn SignResponse missing public_key".into())
    })?;
    {
        use crate::webauthn::{WebAuthnWrapping, verify_webauthn_wrapping_with_policy};
        use p256::ecdsa::VerifyingKey;

        // Explicit SEC1 shape assertion before any verification: a
        // WebAuthn assertion is always P-256, so the returned public key
        // MUST be a valid SEC1 point. `from_sec1_bytes` rejects the
        // wrong length, a non-point, and the identity — defense in depth
        // ahead of `verify_webauthn_wrapping_with_policy`'s own decode.
        let vk = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| {
            Error::ExternalSignerBadResponse(
                "WebAuthn SignResponse public_key is not a valid P-256 SEC1 key".into(),
            )
        })?;
        let authenticator_data = sr.webauthn.authenticator_data.as_deref().ok_or_else(|| {
            Error::ExternalSignerBadResponse(
                "WebAuthn SignResponse missing authenticator_data".into(),
            )
        })?;
        let client_data_json = sr.webauthn.client_data_json.as_deref().ok_or_else(|| {
            Error::ExternalSignerBadResponse(
                "WebAuthn SignResponse missing client_data_json".into(),
            )
        })?;
        let wrapping = WebAuthnWrapping {
            authenticator_data: authenticator_data.to_vec(),
            client_data_json: client_data_json.to_vec(),
        };
        verify_webauthn_wrapping_with_policy(
            pae,
            &wrapping,
            public_key,
            signature,
            webauthn_policy,
        )?;

        let compressed = vk.to_sec1_point(true);
        let canonical = format!("p256:{}", hex_lower(compressed.as_bytes()));
        require_matching_canonical_keyid(key_id, &[("p256", &canonical)])
    }
}

fn validate_ed25519_response(
    public_key: &[u8],
    pae: &[u8],
    signature: &[u8],
    key_id: &str,
) -> Result<(), Error> {
    #[cfg(feature = "algo-ed25519")]
    {
        use crate::verify::{Reason, verify_ed25519};

        let pk: [u8; 32] = public_key.try_into().map_err(|_| {
            Error::ExternalSignerBadResponse(
                "SignResponse public_key is not a 32-byte Ed25519 key".into(),
            )
        })?;
        if verify_ed25519(pk, signature, pae) != Reason::Ok {
            return Err(Error::ExternalSignerBadResponse(
                "SignResponse signature does not verify against public_key".into(),
            ));
        }

        let digest = mkit_core::hash::hash(public_key);
        let blake3_keyid = format!("blake3:{}", mkit_core::hash::to_hex(&digest));
        let raw_keyid = format!("ed25519:{}", hex_lower(public_key));
        require_matching_canonical_keyid(
            key_id,
            &[("blake3", &blake3_keyid), ("ed25519", &raw_keyid)],
        )
    }
    #[cfg(not(feature = "algo-ed25519"))]
    {
        let _ = (public_key, pae, signature, key_id);
        Err(Error::AlgorithmNotEnabled(Algorithm::Ed25519))
    }
}

fn validate_secp256k1_response(
    public_key: &[u8],
    pae: &[u8],
    signature: &[u8],
    key_id: &str,
) -> Result<(), Error> {
    #[cfg(feature = "algo-secp256k1")]
    {
        use crate::signer_k256::verify_secp256k1;
        use k256::ecdsa::VerifyingKey;

        let vk = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| {
            Error::ExternalSignerBadResponse(
                "SignResponse public_key is not a valid secp256k1 SEC1 key".into(),
            )
        })?;
        verify_secp256k1(public_key, pae, signature).map_err(|_| {
            Error::ExternalSignerBadResponse(
                "SignResponse signature does not verify against public_key".into(),
            )
        })?;

        let compressed = vk.to_sec1_point(true);
        let canonical = format!("secp256k1:{}", hex_lower(compressed.as_bytes()));
        require_matching_canonical_keyid(key_id, &[("secp256k1", &canonical)])
    }
    #[cfg(not(feature = "algo-secp256k1"))]
    {
        let _ = (public_key, pae, signature, key_id);
        Err(Error::AlgorithmNotEnabled(Algorithm::Secp256k1))
    }
}

fn validate_p256_response(
    public_key: &[u8],
    pae: &[u8],
    signature: &[u8],
    key_id: &str,
) -> Result<(), Error> {
    #[cfg(feature = "algo-p256")]
    {
        use crate::signer_p256::verify_p256;
        use p256::ecdsa::VerifyingKey;

        let vk = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| {
            Error::ExternalSignerBadResponse(
                "SignResponse public_key is not a valid P-256 SEC1 key".into(),
            )
        })?;
        verify_p256(public_key, pae, signature).map_err(|_| {
            Error::ExternalSignerBadResponse(
                "SignResponse signature does not verify against public_key".into(),
            )
        })?;

        let compressed = vk.to_sec1_point(true);
        let canonical = format!("p256:{}", hex_lower(compressed.as_bytes()));
        require_matching_canonical_keyid(key_id, &[("p256", &canonical)])
    }
    #[cfg(not(feature = "algo-p256"))]
    {
        let _ = (public_key, pae, signature, key_id);
        Err(Error::AlgorithmNotEnabled(Algorithm::P256))
    }
}

fn require_matching_canonical_keyid(
    key_id: &str,
    canonical_by_prefix: &[(&str, &str)],
) -> Result<(), Error> {
    let Some((prefix, _)) = key_id.split_once(':') else {
        return Ok(());
    };
    if let Some((_, canonical)) = canonical_by_prefix
        .iter()
        .find(|(canonical_prefix, _)| *canonical_prefix == prefix)
        && key_id != *canonical
    {
        return Err(Error::ExternalSignerBadResponse(format!(
            "SignResponse key_id mismatch: got {key_id}, expected {canonical}"
        )));
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0F) as usize] as char);
    }
    s
}

/// Require that `frame` is a `HelloResponse` — the version handshake
/// SPEC-EXTERNAL-SIGNER §4 / SPEC-RPC §4 mandates before any other
/// request is processed. A signer that pipelines a `SignResponse` or
/// `Error` straight through, skipping `HelloResponse`, never completed
/// the handshake and is rejected outright rather than tolerated.
fn require_hello_response(frame: &SignerFrame) -> Result<(), Error> {
    match &frame.body {
        Some(signer_frame::Body::HelloResponse(_)) => Ok(()),
        other => Err(Error::ExternalSignerBadResponse(format!(
            "expected HelloResponse as the first frame, got {}",
            frame_name(other)
        ))),
    }
}

/// Decode a wire `PinPrompt` into the protocol-agnostic
/// [`PinPromptInfo`] a [`PinProvider`] consumes.
///
/// `wants_pin` defaults to `true` when the signer leaves it unset: a
/// signer that omits the field is more likely asking for a PIN than a
/// touch (touch-only signers own their own gesture prompt and don't
/// gate on a wire round trip to display it), and prompting when a
/// touch was actually wanted is harmless — the human enters nothing
/// useful and the signer ignores `PinResponse.pin` — whereas silently
/// sending an empty PIN when one really was needed just fails the
/// sign with a confusing hardware error.
fn pin_prompt_info(p: &PinPrompt) -> PinPromptInfo {
    PinPromptInfo {
        reason: p.reason.clone().unwrap_or_default(),
        retries_remaining: p.retries_remaining.unwrap_or(0),
        wants_pin: p.wants_pin.unwrap_or(true),
    }
}

/// Build the `PinResponse` frame sent back on `stdin` in answer to a
/// `PinPrompt`.
fn pin_response_frame(pin: String) -> SignerFrame {
    SignerFrame {
        body: Some(signer_frame::Body::PinResponse(Box::new(
            PinResponse::default().with_pin(pin),
        ))),
        ..Default::default()
    }
}

fn frame_name(b: &Option<signer_frame::Body>) -> &'static str {
    use signer_frame::Body;
    match b {
        Some(Body::Hello(_)) => "hello",
        Some(Body::HelloResponse(_)) => "hello_response",
        Some(Body::SignRequest(_)) => "sign_request",
        Some(Body::SignResponse(_)) => "sign_response",
        Some(Body::PinPrompt(_)) => "pin_prompt",
        Some(Body::PinResponse(_)) => "pin_response",
        Some(Body::Error(_)) => "error",
        None => "(empty body)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_rpc::mkit::rpc::v1::Algorithm as RpcAlgorithm;
    use mkit_rpc::mkit::rpc::v1::signer::WebAuthnData;

    const PAE: &[u8] = b"DSSEv1 28 application/vnd.in-toto+json 2 {}";

    #[test]
    fn new_rejects_relative_path() {
        let err = ExternalSigner::new("mkit-signer").unwrap_err();
        assert!(matches!(err, Error::ExternalSignerRelativePath(_)));
    }

    #[cfg(unix)]
    #[test]
    fn new_accepts_absolute_path() {
        ExternalSigner::new("/usr/bin/foo").expect("absolute path accepted");
    }

    #[cfg(unix)]
    #[test]
    fn with_pin_provider_overrides_default() {
        #[derive(Debug)]
        struct Canned;
        impl PinProvider for Canned {
            fn provide_pin(&self, _prompt: &PinPromptInfo) -> Result<String, Error> {
                Ok("000000".into())
            }
        }
        let signer = ExternalSigner::new("/usr/bin/foo")
            .unwrap()
            .with_pin_provider(Canned);
        assert_eq!(
            signer
                .pin_provider
                .provide_pin(&PinPromptInfo::default())
                .unwrap(),
            "000000"
        );
    }

    #[test]
    fn pin_prompt_info_carries_reason_and_retries() {
        let prompt = PinPrompt::default()
            .with_reason("authenticator locked")
            .with_retries_remaining(2)
            .with_wants_pin(true);
        let info = pin_prompt_info(&prompt);
        assert_eq!(info.reason, "authenticator locked");
        assert_eq!(info.retries_remaining, 2);
        assert!(info.wants_pin);
    }

    #[test]
    fn pin_prompt_info_defaults_wants_pin_true_when_unset() {
        // A signer that omits `wants_pin` is more likely asking for a
        // PIN than a touch — see `pin_prompt_info`'s doc comment.
        let prompt = PinPrompt::default();
        let info = pin_prompt_info(&prompt);
        assert!(info.wants_pin);
        assert_eq!(info.retries_remaining, 0);
        assert_eq!(info.reason, "");
    }

    #[test]
    fn pin_response_frame_round_trips_the_pin() {
        let frame = pin_response_frame("445566".to_owned());
        match frame.body {
            Some(signer_frame::Body::PinResponse(pr)) => {
                assert_eq!(pr.pin.as_deref(), Some("445566"));
            }
            other => panic!("expected PinResponse, got {other:?}"),
        }
    }

    #[test]
    fn require_hello_response_accepts_hello_response() {
        let frame = SignerFrame {
            body: Some(signer_frame::Body::HelloResponse(Box::default())),
            ..Default::default()
        };
        require_hello_response(&frame).expect("HelloResponse must be accepted");
    }

    #[test]
    fn require_hello_response_rejects_sign_response_without_hello() {
        // SPEC-EXTERNAL-SIGNER §4 / SPEC-RPC §4: a signer that pipelines
        // straight to SignResponse, skipping the version handshake,
        // never completed it and must be rejected, not tolerated.
        let frame = SignerFrame {
            body: Some(signer_frame::Body::SignResponse(Box::default())),
            ..Default::default()
        };
        let err = require_hello_response(&frame).unwrap_err();
        assert!(matches!(err, Error::ExternalSignerBadResponse(_)));
        assert!(err.to_string().contains("sign_response"));
    }

    #[test]
    fn require_hello_response_rejects_error_without_hello() {
        let frame = SignerFrame {
            body: Some(signer_frame::Body::Error(Box::default())),
            ..Default::default()
        };
        let err = require_hello_response(&frame).unwrap_err();
        assert!(matches!(err, Error::ExternalSignerBadResponse(_)));
        assert!(err.to_string().contains("error"));
    }

    #[test]
    fn require_hello_response_rejects_empty_body() {
        let frame = SignerFrame {
            body: None,
            ..Default::default()
        };
        let err = require_hello_response(&frame).unwrap_err();
        assert!(matches!(err, Error::ExternalSignerBadResponse(_)));
    }

    #[cfg(feature = "algo-ed25519")]
    fn ed25519_response(key_id: String) -> (SignResponse, Vec<u8>, String) {
        use ed25519_dalek::{Signer as _, SigningKey};

        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let sig = sk.sign(PAE).to_bytes().to_vec();
        let sr = SignResponse::default()
            .with_signature(sig.clone())
            .with_public_key(pk)
            .with_algorithm(RpcAlgorithm::Ed25519)
            .with_key_id(key_id.clone());
        (sr, sig, key_id)
    }

    #[cfg(feature = "algo-ed25519")]
    fn ed25519_keyid(public_key: &[u8]) -> String {
        let digest = mkit_core::hash::hash(public_key);
        format!("blake3:{}", mkit_core::hash::to_hex(&digest))
    }

    #[cfg(feature = "algo-ed25519")]
    #[test]
    fn response_validation_rejects_algorithm_mismatch() {
        let (mut sr, sig, key_id) = ed25519_response("opaque:test".to_owned());
        sr.algorithm = Some(RpcAlgorithm::P256.into());

        let err = validate_sign_response(&sr, Algorithm::Ed25519, PAE, &sig, &key_id).unwrap_err();
        assert!(err.to_string().contains("algorithm mismatch"));
    }

    #[cfg(feature = "algo-ed25519")]
    #[test]
    fn response_validation_rejects_missing_public_key_for_raw_response() {
        let (mut sr, sig, key_id) = ed25519_response("opaque:test".to_owned());
        sr.public_key = None;

        let err = validate_sign_response(&sr, Algorithm::Ed25519, PAE, &sig, &key_id).unwrap_err();
        assert!(err.to_string().contains("missing public_key"));
    }

    /// Regression: an external signer claiming the BLS12-381 threshold
    /// algorithm must be REJECTED, not accepted. There is no
    /// signature-vs-public-key check for the external BLS path, so a
    /// child returning arbitrary signature bytes for a BLS keyid would
    /// otherwise be trusted unverified. The arm must fail closed.
    #[cfg(feature = "bls-threshold")]
    #[test]
    fn response_validation_rejects_bls_threshold_unverified() {
        let key_id = "opaque:bls".to_owned();
        // Attacker-controlled bytes: neither the signature nor the
        // public_key is checked on this arm, so any values would be
        // "accepted" if the arm returned Ok(()).
        let signature = vec![0xAAu8; 48];
        let sr = SignResponse::default()
            .with_signature(signature.clone())
            .with_public_key(vec![0xBBu8; 96])
            .with_algorithm(RpcAlgorithm::Bls12381Threshold)
            .with_key_id(key_id.clone());

        let err =
            validate_sign_response(&sr, Algorithm::Bls12381Threshold, PAE, &signature, &key_id)
                .expect_err(
                    "external BLS-threshold response must be rejected, not trusted unverified",
                );
        assert!(
            matches!(err, Error::ExternalSignerBadResponse(ref m) if m.contains("BLS-threshold")),
            "got {err:?}"
        );
    }

    #[cfg(feature = "algo-p256")]
    #[test]
    fn response_validation_rejects_webauthn_response_without_raw_public_key() {
        let key_id = "opaque:ctap".to_owned();
        let signature = vec![0u8; 64];
        let mut sr = SignResponse::default()
            .with_signature(signature.clone())
            .with_algorithm(RpcAlgorithm::P256)
            .with_key_id(key_id.clone());
        sr.webauthn = buffa::MessageField::some(
            WebAuthnData::default()
                .with_authenticator_data(vec![0u8; 37])
                .with_client_data_json(b"{}".to_vec()),
        );

        let err = validate_sign_response(&sr, Algorithm::P256, PAE, &signature, &key_id)
            .expect_err("WebAuthn marker must not bypass public key validation");
        assert!(err.to_string().contains("missing public_key"));
    }

    #[cfg(feature = "algo-p256")]
    #[test]
    fn response_validation_rejects_webauthn_response_with_bad_signature() {
        use crate::signer_p256::P256Signer;

        let signer = P256Signer::new([0x33; 32]).unwrap();
        let key_id = signer.keyid();
        let signature = vec![0u8; 64];
        let mut sr = SignResponse::default()
            .with_signature(signature.clone())
            .with_public_key(signer.public_key_sec1_uncompressed())
            .with_algorithm(RpcAlgorithm::P256)
            .with_key_id(key_id.clone());
        sr.webauthn = buffa::MessageField::some(
            WebAuthnData::default()
                .with_authenticator_data(vec![0u8; 37])
                .with_client_data_json(crate::webauthn::build_client_data_json(
                    PAE,
                    "https://example.test",
                    false,
                )),
        );

        let err = validate_sign_response(&sr, Algorithm::P256, PAE, &signature, &key_id)
            .expect_err("WebAuthn marker must not bypass assertion verification");
        assert!(matches!(err, Error::WebAuthnSignatureFailed), "got {err:?}");
    }

    #[cfg(feature = "algo-p256")]
    #[test]
    fn response_validation_allows_webauthn_response_with_valid_assertion() {
        use crate::signer_p256::P256Signer;
        use sha2::{Digest, Sha256};

        let signer = P256Signer::new([0x33; 32]).unwrap();
        let key_id = signer.keyid();
        let authenticator_data = vec![0u8; 37];
        let client_data_json =
            crate::webauthn::build_client_data_json(PAE, "https://example.test", false);
        let mut signed_payload = authenticator_data.clone();
        signed_payload.extend_from_slice(&Sha256::digest(&client_data_json));
        let signature = signer.sign_dsse(&signed_payload).unwrap();
        let mut sr = SignResponse::default()
            .with_signature(signature.clone())
            .with_public_key(signer.public_key_sec1_uncompressed())
            .with_algorithm(RpcAlgorithm::P256)
            .with_key_id(key_id.clone());
        sr.webauthn = buffa::MessageField::some(
            WebAuthnData::default()
                .with_authenticator_data(authenticator_data)
                .with_client_data_json(client_data_json),
        );

        validate_sign_response(&sr, Algorithm::P256, PAE, &signature, &key_id)
            .expect("WebAuthn response verifies assertion binding and signature");
    }

    #[cfg(feature = "algo-ed25519")]
    #[test]
    fn response_validation_rejects_signature_mismatch() {
        let (mut sr, mut sig, key_id) = ed25519_response("opaque:test".to_owned());
        sig[0] ^= 0x01;
        sr.signature = Some(sig.clone());

        let err = validate_sign_response(&sr, Algorithm::Ed25519, PAE, &sig, &key_id).unwrap_err();
        assert!(err.to_string().contains("signature does not verify"));
    }

    #[cfg(feature = "algo-ed25519")]
    #[test]
    fn response_validation_checks_ed25519_canonical_keyids_but_allows_opaque() {
        let (sr, sig, key_id) = ed25519_response("opaque:test".to_owned());
        validate_sign_response(&sr, Algorithm::Ed25519, PAE, &sig, &key_id)
            .expect("opaque key_id remains allowed");

        let public_key = sr.public_key.as_deref().unwrap();
        let canonical_keyid = ed25519_keyid(public_key);
        let (sr, sig, key_id) = ed25519_response(canonical_keyid);
        validate_sign_response(&sr, Algorithm::Ed25519, PAE, &sig, &key_id)
            .expect("canonical key_id matches returned public key");

        let (sr, sig, key_id) = ed25519_response("blake3:00".to_owned());
        let err = validate_sign_response(&sr, Algorithm::Ed25519, PAE, &sig, &key_id).unwrap_err();
        assert!(err.to_string().contains("key_id mismatch"));
    }

    #[cfg(feature = "algo-secp256k1")]
    #[test]
    fn response_validation_checks_secp256k1_canonical_keyid() {
        use crate::signer_k256::Secp256k1Signer;

        let mut secret = [0u8; 32];
        secret[31] = 7;
        let signer = Secp256k1Signer::new(secret).unwrap();
        let sig = signer.sign_dsse(PAE).unwrap();
        let key_id = signer.keyid_string();
        let sr = SignResponse::default()
            .with_signature(sig.clone())
            .with_public_key(signer.public_key_sec1())
            .with_algorithm(RpcAlgorithm::Secp256k1)
            .with_key_id(key_id.clone());
        validate_sign_response(&sr, Algorithm::Secp256k1, PAE, &sig, &key_id)
            .expect("canonical secp256k1 key_id matches returned public key");

        let bad_key_id = "secp256k1:00".to_owned();
        let bad = SignResponse::default()
            .with_signature(sig.clone())
            .with_public_key(signer.public_key_sec1())
            .with_algorithm(RpcAlgorithm::Secp256k1)
            .with_key_id(bad_key_id.clone());
        let err =
            validate_sign_response(&bad, Algorithm::Secp256k1, PAE, &sig, &bad_key_id).unwrap_err();
        assert!(err.to_string().contains("key_id mismatch"));
    }

    #[cfg(feature = "algo-p256")]
    #[test]
    fn response_validation_checks_p256_canonical_keyid() {
        use crate::signer_p256::P256Signer;

        let secret = [0x33; 32];
        let signer = P256Signer::new(secret).unwrap();
        let sig = signer.sign_dsse(PAE).unwrap();
        let key_id = signer.keyid();
        let sr = SignResponse::default()
            .with_signature(sig.clone())
            .with_public_key(signer.public_key_sec1())
            .with_algorithm(RpcAlgorithm::P256)
            .with_key_id(key_id.clone());
        validate_sign_response(&sr, Algorithm::P256, PAE, &sig, &key_id)
            .expect("canonical P-256 key_id matches returned public key");

        let bad_key_id = "p256:00".to_owned();
        let bad = SignResponse::default()
            .with_signature(sig.clone())
            .with_public_key(signer.public_key_sec1())
            .with_algorithm(RpcAlgorithm::P256)
            .with_key_id(bad_key_id.clone());
        let err =
            validate_sign_response(&bad, Algorithm::P256, PAE, &sig, &bad_key_id).unwrap_err();
        assert!(err.to_string().contains("key_id mismatch"));
    }

    // -- Bounded-execution tests (unix-gated spawn tests) -----------
    //
    // Each test writes a tiny `#!/bin/sh` child to a tempdir, chmods it
    // +x, and drives an `ExternalSigner` against it with a short timeout
    // so the suite stays fast. Mirrors the SSH transport's
    // `wait_child_timeout_kills_stalled_child` style.
    #[cfg(all(unix, feature = "algo-ed25519"))]
    mod bounded {
        use super::*;
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;
        use std::time::Duration;

        /// Write `script` to a tempdir as an executable, returning the
        /// tempdir (kept alive) and the absolute path to the binary.
        fn write_script(script: &str) -> (tempfile::TempDir, std::path::PathBuf) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("signer.sh");
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(script.as_bytes()).unwrap();
            f.flush().unwrap();
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).unwrap();
            (dir, path)
        }

        /// Exact byte length of the Hello + `SignRequest` frames
        /// `ExternalSigner::sign` writes for `(Algorithm::Ed25519, PAE)`.
        ///
        /// The host now keeps the child's stdin open for the whole
        /// conversation (so a mid-sign `PinPrompt` can be answered on
        /// it — see `spawn_request_writer`), so a script fixture can no
        /// longer drain the initial request with `cat >/dev/null`: that
        /// blocks on EOF, which never comes until *after* the host has
        /// read a terminal frame — a fixture that blocks on EOF before
        /// writing anything would deadlock. Fixtures instead read
        /// exactly this many bytes via `dd bs=1 count=N`.
        fn initial_request_len() -> usize {
            let hello = SignerFrame {
                body: Some(signer_frame::Body::Hello(Box::new(
                    Hello::default()
                        .with_protocol(ProtocolVersion::ProtocolVersion1)
                        .with_caller_id(format!("mkit-attest/{}", env!("CARGO_PKG_VERSION")))
                        .with_want_capabilities(false),
                ))),
                ..Default::default()
            };
            let sign_req = SignerFrame {
                body: Some(signer_frame::Body::SignRequest(Box::new(
                    SignRequest::default()
                        .with_algorithm(RpcAlgorithm::Ed25519)
                        .with_key_form(KeyForm::RawBytes)
                        .with_key_ref(Vec::new())
                        .with_payload(PAE.to_vec())
                        .with_context(Vec::new()),
                ))),
                ..Default::default()
            };
            let mut buf = Vec::new();
            write_frame(&mut buf, &hello).unwrap();
            write_frame(&mut buf, &sign_req).unwrap();
            buf.len()
        }

        /// Shell snippet that drains exactly the initial Hello +
        /// `SignRequest` request off stdin without relying on EOF.
        fn drain_initial_request() -> String {
            format!(
                "dd bs=1 count={} 2>/dev/null >/dev/null\n",
                initial_request_len()
            )
        }

        /// Serialize a valid Ed25519 `SignResponse` (Hello + `SignResponse`)
        /// to a length-prefixed frame byte stream, base64-free, written
        /// to a file the child can `cat`.
        fn valid_response_frames_file(dir: &std::path::Path) -> std::path::PathBuf {
            use ed25519_dalek::{Signer as _, SigningKey};

            let sk = SigningKey::from_bytes(&[0x42; 32]);
            let pk = sk.verifying_key().to_bytes().to_vec();
            let sig = sk.sign(PAE).to_bytes().to_vec();
            let hello_resp = SignerFrame {
                body: Some(signer_frame::Body::HelloResponse(Box::<
                    mkit_rpc::mkit::rpc::v1::signer::HelloResponse,
                >::default(
                ))),
                ..Default::default()
            };
            let sign_resp = SignerFrame {
                body: Some(signer_frame::Body::SignResponse(Box::new(
                    SignResponse::default()
                        .with_signature(sig)
                        .with_public_key(pk)
                        .with_algorithm(RpcAlgorithm::Ed25519)
                        .with_key_id("opaque:test".to_owned()),
                ))),
                ..Default::default()
            };
            let mut bytes = Vec::new();
            write_frame(&mut bytes, &hello_resp).unwrap();
            write_frame(&mut bytes, &sign_resp).unwrap();
            let path = dir.join("response.bin");
            std::fs::write(&path, &bytes).unwrap();
            path
        }

        #[test]
        // #505 PR 5/5: real subprocess + wall-clock timeout, several
        // seconds of real sleep total across this module's three tests.
        // Quarantined to the serial `--ignored` CI lane (cloudbuild/ci.yaml,
        // .github/workflows/rust.yml) instead of running on every `cargo test`.
        #[ignore = "real subprocess + wall-clock timeout; run via the serial --ignored CI lane"]
        fn hang_before_stdout_times_out_and_reaps_child() {
            // Child reads stdin then sleeps forever without writing
            // stdout — the classic "hung on a touch that never comes".
            let script = format!("#!/bin/sh\n{}sleep 600\n", drain_initial_request());
            let (_dir, path) = write_script(&script);
            let mut signer = ExternalSigner::new(&path)
                .unwrap()
                .with_timeout(Duration::from_millis(300));
            let err = signer.sign(PAE).expect_err("must time out");
            // A hung child must produce a bounded timeout. The expected
            // phase is `response-read` (the child reads stdin then sleeps
            // without writing stdout), but under heavy CPU load an earlier
            // phase (e.g. request-write) can consume the budget first, so
            // we assert only that it is a bounded timeout.
            assert!(
                matches!(err, Error::ExternalSignerTimeout(_)),
                "expected a bounded timeout, got {err:?}"
            );
            // No assertion on the child handle (it's dropped inside
            // sign), but the call returned promptly which proves the
            // child was killed+reaped rather than blocking forever.
        }

        #[test]
        // #505 PR 5/5: quarantined alongside the other two subprocess-sleep
        // tests in this module — see `hang_before_stdout_times_out_and_reaps_child`.
        #[ignore = "real subprocess + wall-clock timeout; run via the serial --ignored CI lane"]
        fn fills_stderr_before_stdout_does_not_deadlock() {
            // Child floods stderr (well past a pipe buffer) BEFORE
            // emitting any stdout, then hangs. Without the concurrent
            // stderr drain this would deadlock; with it, we still hit the
            // response-read timeout cleanly (bounded, no hang).
            let script = format!(
                "#!/bin/sh\n{}\
                 yes deadlock-flood-line | head -c 2000000 1>&2\n\
                 sleep 600\n",
                drain_initial_request(),
            );
            let (_dir, path) = write_script(&script);
            let mut signer = ExternalSigner::new(&path)
                .unwrap()
                .with_timeout(Duration::from_millis(500));
            let err = signer
                .sign(PAE)
                .expect_err("must not deadlock; must time out");
            // The load-bearing property here is "no deadlock": with the
            // concurrent stderr drain the call returns a bounded timeout
            // instead of wedging forever. The expected phase is
            // `response-read`, but as with the other bounded tests an
            // earlier phase can trip first under CPU load, so we assert
            // only on boundedness.
            assert!(
                matches!(err, Error::ExternalSignerTimeout(_)),
                "expected a bounded timeout (no deadlock), got {err:?}"
            );
        }

        #[test]
        // #505 PR 5/5: quarantined alongside the other two subprocess-sleep
        // tests in this module — see `hang_before_stdout_times_out_and_reaps_child`.
        #[ignore = "real subprocess + wall-clock timeout; run via the serial --ignored CI lane"]
        fn valid_response_then_never_exits_is_bounded() {
            // Child emits a valid Hello+SignResponse, then sleeps forever
            // without closing. We must still bound the wait: the response
            // is consumed but the child-exit phase trips the deadline.
            let dir = tempfile::tempdir().unwrap();
            let resp = valid_response_frames_file(dir.path());
            let script = format!(
                "#!/bin/sh\n{}cat '{}'\nsleep 600\n",
                drain_initial_request(),
                resp.display()
            );
            let bin = dir.path().join("signer.sh");
            std::fs::write(&bin, script).unwrap();
            let mut perms = std::fs::metadata(&bin).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&bin, perms).unwrap();

            let mut signer = ExternalSigner::new(&bin)
                .unwrap()
                .with_timeout(Duration::from_millis(1500));
            let err = signer
                .sign(PAE)
                .expect_err("valid response but no exit must trip a bounded timeout");
            // The acceptance criterion is BOUNDEDNESS: a signer that emits
            // a valid response then never exits must return *some* timeout
            // rather than hang. Which phase trips first
            // (response-read / stderr-drain / child-exit) is scheduling-
            // dependent — under CPU load the response-read budget can be
            // consumed before the child's stdout is ever scheduled — so we
            // assert only that it is a bounded timeout, not a specific
            // phase. The point proven is "no hang", which the prompt
            // return promptly already demonstrates.
            assert!(
                matches!(err, Error::ExternalSignerTimeout(_)),
                "expected a bounded timeout, got {err:?}"
            );
        }

        #[test]
        fn valid_response_and_clean_exit_succeeds() {
            // Control: the same valid response, but the child exits
            // promptly. This must succeed within the timeout, proving the
            // bounded path doesn't break the happy case.
            let dir = tempfile::tempdir().unwrap();
            let resp = valid_response_frames_file(dir.path());
            let script = format!(
                "#!/bin/sh\n{}cat '{}'\n",
                drain_initial_request(),
                resp.display()
            );
            let bin = dir.path().join("signer.sh");
            std::fs::write(&bin, script).unwrap();
            let mut perms = std::fs::metadata(&bin).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&bin, perms).unwrap();

            // Generous budget on purpose: this test asserts SUCCESS, so a
            // tight wall-clock would false-fail on a loaded CI box where
            // the spawned shell can't be scheduled promptly (a saturated
            // machine has been observed to delay a trivial `cat` by
            // several seconds). The point of the test is that the bounded
            // path doesn't break the happy case, not how fast it is — so
            // the timeout only needs to be comfortably above any realistic
            // scheduling delay.
            let mut signer = ExternalSigner::new(&bin)
                .unwrap()
                .with_timeout(Duration::from_secs(30));
            let sig = signer.sign(PAE).expect("happy path within timeout");
            assert_eq!(sig.len(), 64, "Ed25519 signature is 64 bytes");
            assert_eq!(signer.keyid().unwrap(), "opaque:test");
        }

        #[test]
        fn signer_that_skips_hello_response_is_rejected() {
            // #558 / SPEC-EXTERNAL-SIGNER §4 / SPEC-RPC §4: a signer that
            // pipelines straight to a valid SignResponse, never sending
            // HelloResponse, never completed the version handshake and
            // must be rejected outright rather than tolerated as it was
            // before this fix.
            use ed25519_dalek::{Signer as _, SigningKey};

            let dir = tempfile::tempdir().unwrap();
            let sk = SigningKey::from_bytes(&[0x42; 32]);
            let pk = sk.verifying_key().to_bytes().to_vec();
            let sig = sk.sign(PAE).to_bytes().to_vec();
            let sign_resp = SignerFrame {
                body: Some(signer_frame::Body::SignResponse(Box::new(
                    SignResponse::default()
                        .with_signature(sig)
                        .with_public_key(pk)
                        .with_algorithm(RpcAlgorithm::Ed25519)
                        .with_key_id("opaque:test".to_owned()),
                ))),
                ..Default::default()
            };
            let mut bytes = Vec::new();
            write_frame(&mut bytes, &sign_resp).unwrap();
            let resp = dir.path().join("response.bin");
            std::fs::write(&resp, &bytes).unwrap();

            let script = format!(
                "#!/bin/sh\n{}cat '{}'\n",
                drain_initial_request(),
                resp.display()
            );
            let bin = dir.path().join("signer.sh");
            std::fs::write(&bin, script).unwrap();
            let mut perms = std::fs::metadata(&bin).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&bin, perms).unwrap();

            let mut signer = ExternalSigner::new(&bin)
                .unwrap()
                .with_timeout(Duration::from_secs(30));
            let err = signer
                .sign(PAE)
                .expect_err("a signer that skips HelloResponse must be rejected");
            assert!(
                matches!(err, Error::ExternalSignerBadResponse(_)),
                "expected ExternalSignerBadResponse, got {err:?}"
            );
            assert!(err.to_string().contains("HelloResponse"));
        }

        #[test]
        fn pin_prompt_round_trip_completes_sign() {
            // SPEC-EXTERNAL-SIGNER §4: the signer MAY interleave a
            // PinPrompt before its terminal response. The child here
            // drains the initial request, emits HelloResponse +
            // PinPrompt, drains the exact-length PinResponse the host
            // sends back, then emits a valid SignResponse — proving the
            // host (a) doesn't fall into `extract_signature`'s `other`
            // arm on a PinPrompt, (b) invokes the configured
            // `PinProvider`, (c) writes a well-formed `PinResponse` on
            // the still-open stdin without deadlocking, and (d)
            // completes signing.
            #[derive(Debug, Clone)]
            struct FakePinProvider {
                seen: std::rc::Rc<std::cell::RefCell<Vec<PinPromptInfo>>>,
                pin: String,
            }
            impl PinProvider for FakePinProvider {
                fn provide_pin(&self, prompt: &PinPromptInfo) -> Result<String, Error> {
                    self.seen.borrow_mut().push(prompt.clone());
                    Ok(self.pin.clone())
                }
            }

            const TEST_PIN: &str = "445566";

            let dir = tempfile::tempdir().unwrap();

            let hello_and_prompt = {
                let hello_resp = SignerFrame {
                    body: Some(signer_frame::Body::HelloResponse(Box::<
                        mkit_rpc::mkit::rpc::v1::signer::HelloResponse,
                    >::default(
                    ))),
                    ..Default::default()
                };
                let prompt = SignerFrame {
                    body: Some(signer_frame::Body::PinPrompt(Box::new(
                        PinPrompt::default()
                            .with_reason("authenticator locked")
                            .with_retries_remaining(3)
                            .with_wants_pin(true),
                    ))),
                    ..Default::default()
                };
                let mut buf = Vec::new();
                write_frame(&mut buf, &hello_resp).unwrap();
                write_frame(&mut buf, &prompt).unwrap();
                let path = dir.path().join("hello_and_prompt.bin");
                std::fs::write(&path, &buf).unwrap();
                path
            };

            // The exact wire length of the `PinResponse` the host will
            // send back once `FakePinProvider` supplies `TEST_PIN` — so
            // the fixture can drain it precisely instead of racing EOF.
            let pin_response_len = {
                let frame = pin_response_frame(TEST_PIN.to_owned());
                let mut buf = Vec::new();
                write_frame(&mut buf, &frame).unwrap();
                buf.len()
            };

            // Just the `SignResponse` — the `HelloResponse` already went
            // out in `hello_and_prompt` above, so reusing
            // `valid_response_frames_file` here would send a second one
            // and desync the host's terminal-frame read.
            let sign_response = {
                use ed25519_dalek::{Signer as _, SigningKey};
                let sk = SigningKey::from_bytes(&[0x42; 32]);
                let pk = sk.verifying_key().to_bytes().to_vec();
                let sig = sk.sign(PAE).to_bytes().to_vec();
                let sign_resp = SignerFrame {
                    body: Some(signer_frame::Body::SignResponse(Box::new(
                        SignResponse::default()
                            .with_signature(sig)
                            .with_public_key(pk)
                            .with_algorithm(RpcAlgorithm::Ed25519)
                            .with_key_id("opaque:test".to_owned()),
                    ))),
                    ..Default::default()
                };
                let mut buf = Vec::new();
                write_frame(&mut buf, &sign_resp).unwrap();
                let path = dir.path().join("sign_response.bin");
                std::fs::write(&path, &buf).unwrap();
                path
            };

            let script = format!(
                "#!/bin/sh\n{}cat '{}'\ndd bs=1 count={} 2>/dev/null >/dev/null\ncat '{}'\n",
                drain_initial_request(),
                hello_and_prompt.display(),
                pin_response_len,
                sign_response.display(),
            );
            let bin = dir.path().join("signer.sh");
            std::fs::write(&bin, script).unwrap();
            let mut perms = std::fs::metadata(&bin).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&bin, perms).unwrap();

            let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
            let provider = FakePinProvider {
                seen: std::rc::Rc::clone(&seen),
                pin: TEST_PIN.to_owned(),
            };

            let mut signer = ExternalSigner::new(&bin)
                .unwrap()
                .with_timeout(Duration::from_secs(30))
                .with_pin_provider(provider);
            let sig = signer
                .sign(PAE)
                .expect("PinPrompt round trip must complete signing");
            assert_eq!(sig.len(), 64, "Ed25519 signature is 64 bytes");
            assert_eq!(signer.keyid().unwrap(), "opaque:test");

            let seen = seen.borrow();
            assert_eq!(seen.len(), 1, "PinProvider must be invoked exactly once");
            assert_eq!(seen[0].reason, "authenticator locked");
            assert_eq!(seen[0].retries_remaining, 3);
            assert!(seen[0].wants_pin);
        }
    }
}
