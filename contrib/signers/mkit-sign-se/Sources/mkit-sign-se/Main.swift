// main.swift — CLI entry for mkit-sign-se.
//
// Subcommands:
//
//     mkit-sign-se keygen --tag <label> [--require-biometric]
//     mkit-sign-se sign   [--tag <label>]
//     mkit-sign-se list
//     mkit-sign-se delete --tag <label>
//
// The `sign` subcommand is what mkit drives as an external signer; it
// speaks the v1 wire protocol — length-prefixed protobuf `SignerFrame`
// messages on stdin/stdout. See `docs/specs/SPEC-EXTERNAL-SIGNER.md` and
// `rust/crates/mkit-rpc/proto/signer.proto`.
//
// The tag identifying the Secure Enclave key can be supplied two ways:
//
//   * `--tag <label>` on argv, which sets a per-process default (handy
//     when mkit's external-signer plumbing passes the key id through
//     argv rather than the wire).
//   * `SignRequest.key_ref` on the wire, interpreted as the UTF-8
//     bytes of the tag (`KEY_FORM_OPAQUE_HANDLE`). When both are set,
//     the wire value wins.
//
// Setup-phase errors (no Secure Enclave on the host, bad argv,
// unknown subcommand) exit non-zero with a stderr message. Per-request
// errors during `sign` are returned as `SignerFrame.Error` frames and
// the loop continues — matching the protocol's "callers MAY send
// multiple requests on a single connection" contract.

import CryptoKit
import Foundation

// MARK: - Error type

enum SignerError: Error, CustomStringConvertible {
    case usage(String)
    case unknownSubcommand(String)
    case missingTag
    case unsupportedAlgorithm(String)
    case secureEnclaveUnavailable
    case tagNotFound(String)
    case tagAlreadyExists(String)
    case keychain(OSStatus)
    case accessControl(String)
    case biometricDeclined
    case malformedDERSignature
    case malformedPublicKey
    case protocolFatal(String)
    case io(String)

    var description: String {
        switch self {
        case .usage(let msg):
            return msg
        case .unknownSubcommand(let s):
            return "unknown subcommand `\(s)` (want keygen|sign|list|delete)"
        case .missingTag:
            return "missing --tag <label>"
        case .unsupportedAlgorithm(let a):
            return
                "algorithm `\(a)` not supported — Secure Enclave is P-256 only"
        case .secureEnclaveUnavailable:
            return "Secure Enclave not available on this device"
        case .tagNotFound(let t):
            return
                "no Secure Enclave key with tag '\(t)' — run `mkit-sign-se keygen --tag \(t)` first"
        case .tagAlreadyExists(let t):
            return
                "a Secure Enclave key with tag '\(t)' already exists — delete it first with `mkit-sign-se delete --tag \(t)`"
        case .keychain(let status):
            return "keychain error: \(status) (\(secErrorMessage(status)))"
        case .accessControl(let msg):
            return "access-control creation failed: \(msg)"
        case .biometricDeclined:
            return "biometric prompt was declined or cancelled"
        case .malformedDERSignature:
            return "malformed DER ECDSA signature"
        case .malformedPublicKey:
            return "malformed P-256 public key"
        case .protocolFatal(let s):
            return "protocol: \(s)"
        case .io(let s):
            return "io: \(s)"
        }
    }
}

private func secErrorMessage(_ status: OSStatus) -> String {
    if let msg = SecCopyErrorMessageString(status, nil) as String? {
        return msg
    }
    return "status \(status)"
}

// MARK: - Argv parsing

struct ParsedArgs {
    var tag: String?
    var requireBiometric: Bool = false

    static func parse(_ args: [String]) throws -> ParsedArgs {
        var out = ParsedArgs()
        var i = 0
        while i < args.count {
            let a = args[i]
            switch a {
            case "--tag":
                i += 1
                guard i < args.count else {
                    throw SignerError.usage("--tag needs a value")
                }
                out.tag = args[i]
            case "--require-biometric":
                out.requireBiometric = true
            case "-h", "--help":
                throw SignerError.usage(Self.helpText)
            default:
                throw SignerError.usage("unknown flag `\(a)`")
            }
            i += 1
        }
        return out
    }

    static let helpText = """
        mkit-sign-se: Apple Secure Enclave external signer for mkit (P-256 only)

        USAGE:
            mkit-sign-se keygen --tag <label> [--require-biometric]
            mkit-sign-se sign   [--tag <label>]
            mkit-sign-se list
            mkit-sign-se delete --tag <label>

        `sign` speaks the v1 external-signer wire protocol — length-prefixed
        protobuf SignerFrame messages on stdin/stdout. See
        docs/specs/SPEC-EXTERNAL-SIGNER.md for the protocol surface.

        The P-256 key lives in the Secure Enclave and is non-extractable by
        design. `--require-biometric` on keygen makes signing prompt for
        Touch ID / Face ID.

        For `sign`, the tag may be provided via `--tag` (argv default) or
        via `SignRequest.key_ref` (UTF-8 bytes of the tag) over the wire.
        Wire wins when both are set.
        """
}

// Kept in step with the reference-signer workspace version
// (contrib/signers/Cargo.toml) so all signers advertise the same
// `signer_id` version component.
private let signerVersion = "0.1.0"

// MARK: - Subcommand implementations

func runKeygen(_ parsed: ParsedArgs) throws {
    guard let tag = parsed.tag else { throw SignerError.missingTag }
    let key = try SecureEnclaveKey.create(tag: tag, requireBiometric: parsed.requireBiometric)
    let keyid = try key.keyidString()
    FileHandle.standardOutput.write(Data((keyid + "\n").utf8))
    // Short human-readable note to stderr so piping stdout to a
    // capture buffer still yields just the keyid.
    let bio = parsed.requireBiometric ? " (biometric-gated)" : ""
    FileHandle.standardError.write(
        Data("created Secure Enclave key tag='\(tag)'\(bio)\n".utf8))
}

func runSign(_ parsed: ParsedArgs) throws {
    let reader = FileHandleReader(handle: FileHandle.standardInput)
    let writer = FileHandleWriter(handle: FileHandle.standardOutput)
    try serve(reader: reader, writer: writer, defaultTag: parsed.tag)
}

func runList() throws {
    let items = try SecureEnclaveKey.list()
    var buf = ""
    for (tag, hex) in items {
        buf += "\(tag)\t\(hex)\n"
    }
    FileHandle.standardOutput.write(Data(buf.utf8))
}

func runDelete(_ parsed: ParsedArgs) throws {
    guard let tag = parsed.tag else { throw SignerError.missingTag }
    try SecureEnclaveKey.delete(tag: tag)
    FileHandle.standardError.write(Data("deleted tag='\(tag)'\n".utf8))
}

// MARK: - serve

/// Read frames until stdin closes, dispatching on the `body` oneof and
/// writing exactly one response frame per request.
///
/// Per-request failures are returned as `Error` frames; the loop
/// continues. Protocol-level fatals (oversize frame, decode failure)
/// emit one terminal `Error` frame and throw, so `Main.main` exits
/// non-zero.
///
/// `defaultTag` is the argv-level tag default; per-request the wire
/// `SignRequest.key_ref` (interpreted as UTF-8 bytes of the tag) takes
/// precedence when non-empty.
func serve(reader: FrameReader, writer: FrameWriter, defaultTag: String?) throws {
    while true {
        let frame: SignerFrame
        do {
            guard let f = try readFrame(reader) else {
                // Clean EOF between frames — caller closed stdin. Exit
                // success; this matches the file signer's behaviour.
                return
            }
            frame = f
        } catch FrameError.lengthTooLarge(let n) {
            try? writeFrame(
                errorFrame(.invalidRequest, "frame length \(n) exceeds 1 MiB cap"),
                to: writer
            )
            throw SignerError.protocolFatal("oversize frame (\(n) bytes)")
        } catch FrameError.bodyTruncated(let expected, _) {
            try? writeFrame(
                errorFrame(.invalidRequest, "frame body truncated (expected \(expected) bytes)"),
                to: writer
            )
            throw SignerError.protocolFatal("truncated frame body")
        } catch FrameError.lengthPrefixTruncated {
            try? writeFrame(
                errorFrame(.invalidRequest, "frame length prefix truncated"),
                to: writer
            )
            throw SignerError.protocolFatal("truncated length prefix")
        } catch FrameError.decodeFailed(let msg) {
            try? writeFrame(
                errorFrame(.invalidRequest, "frame failed to decode as SignerFrame: \(msg)"),
                to: writer
            )
            throw SignerError.protocolFatal("decode failure")
        }

        switch frame.body {
        case .some(.hello):
            // Always reply with capabilities. The wire is cheap enough
            // that gating on `want_capabilities` adds complexity
            // without a payoff. We advertise `requires_user_presence
            // = true` because any biometric-gated SEP key needs the
            // user to approve; mkit treats this as a UI hint.
            let resp = helloResponseFrame(
                signerVersion: signerVersion,
                requiresUserPresence: true
            )
            try writeFrame(resp, to: writer)

        case .some(.signRequest(let req)):
            let resp = handleSign(req, defaultTag: defaultTag)
            try writeFrame(resp, to: writer)

        case .some(.pinResponse):
            // The SE signer never emits a PinPrompt, so a stray
            // PinResponse from the caller is a protocol error.
            try writeFrame(
                errorFrame(.invalidRequest, "mkit-sign-se does not request a PIN"),
                to: writer
            )

        case .some(.helloResponse), .some(.signResponse), .some(.pinPrompt), .some(.error):
            try writeFrame(
                errorFrame(.invalidRequest, "unexpected server-only frame variant from caller"),
                to: writer
            )

        case .none:
            try writeFrame(
                errorFrame(.invalidRequest, "empty frame body"),
                to: writer
            )
        }
    }
}

/// Resolve the tag for a `SignRequest`: wire `key_ref` wins (interpreted
/// as the UTF-8 bytes of the tag, matching the `OPAQUE_HANDLE` key form
/// described in `signer.proto`); fall back to the argv default. Returns
/// `nil` if neither is set, which becomes an `INVALID_REQUEST` error.
private func resolveTag(_ req: SignRequest, defaultTag: String?) -> String? {
    if !req.keyRef.isEmpty {
        // The OPAQUE_HANDLE bytes are interpreted by the signer; for
        // mkit-sign-se the convention is "UTF-8 bytes of the keychain
        // tag". A non-UTF-8 key_ref is treated as missing.
        if let s = String(data: req.keyRef, encoding: .utf8), !s.isEmpty {
            return s
        }
    }
    return defaultTag
}

/// Sign one `SignRequest`. Returns the response frame to send (which
/// may be a `SignResponse` or an `Error`). Per-request errors never
/// throw out of here — they all become Error frames.
func handleSign(_ req: SignRequest, defaultTag: String?) -> SignerFrame {
    // Algorithm: only P-256 is meaningful for the Secure Enclave.
    // `ALGORITHM_UNSPECIFIED` (0) is treated as a request error rather
    // than a polite default to P-256 — callers should be explicit.
    let alg = req.algorithm
    if alg != .p256 {
        return errorFrame(
            .unsupportedAlgorithm,
            "Secure Enclave is P-256 only (got \(rpcAlgorithmName(alg)))"
        )
    }

    // Key form: only OPAQUE_HANDLE. `UNSPECIFIED` (0) is tolerated
    // when the argv `--tag` default has been set — same posture as
    // the file signer accepts an unset key_form alongside its argv
    // `--key`.
    let kf = req.keyForm
    if kf != .opaqueHandle && kf != .unspecified {
        return errorFrame(
            .unsupportedKeyForm,
            "mkit-sign-se only supports KEY_FORM_OPAQUE_HANDLE (got \(rpcKeyFormName(kf)))"
        )
    }

    guard let tag = resolveTag(req, defaultTag: defaultTag) else {
        return errorFrame(
            .invalidRequest,
            "no key tag — pass --tag on argv or set SignRequest.key_ref to UTF-8 tag bytes"
        )
    }

    let key: SecureEnclave.P256.Signing.PrivateKey
    do {
        key = try SecureEnclaveKey.load(tag: tag)
    } catch SignerError.tagNotFound(let t) {
        return errorFrame(.keyNotFound, "no Secure Enclave key with tag '\(t)'")
    } catch SignerError.secureEnclaveUnavailable {
        return errorFrame(.hardwareError, "Secure Enclave not available on this device")
    } catch SignerError.keychain(let status) {
        return errorFrame(.hardwareError, "keychain error \(status): \(secErrorMessage(status))")
    } catch {
        return errorFrame(.internal, "load tag '\(tag)': \(error)")
    }

    let pae = req.payload
    let digest = SHA256.hash(data: pae)
    let sig: P256.Signing.ECDSASignature
    do {
        sig = try key.signature(for: digest)
    } catch {
        // CryptoKit surfaces user-cancel as a CFErrorRef bridged into
        // NSError with the LocalAuthentication domain — map that to
        // USER_DECLINED so the caller can distinguish a deliberate
        // cancel from a generic hardware failure.
        let nsErr = error as NSError
        let userCancelled =
            nsErr.domain.contains("LocalAuthentication")
            || nsErr.code == -128
            || nsErr.code == errSecUserCanceled
        if userCancelled {
            return errorFrame(
                .userDeclined,
                "biometric prompt declined or cancelled"
            )
        }
        return errorFrame(.hardwareError, "sign: \(error.localizedDescription)")
    }

    // `rawRepresentation` on P256.Signing.ECDSASignature is the
    // 64-byte compact `r || s` form the v1 wire requires.
    let compact = sig.rawRepresentation
    if compact.count != 64 {
        return errorFrame(
            .internal,
            "expected 64-byte compact ECDSA signature, got \(compact.count) bytes"
        )
    }

    let compressed: Data
    let keyid: String
    do {
        compressed = try compressSEC1FromRaw(key.publicKey.rawRepresentation)
        keyid = "p256:" + hexLower(compressed)
    } catch {
        return errorFrame(.internal, "compress public key: \(error)")
    }

    return signResponseFrame(
        signature: compact,
        publicKey: compressed,
        keyID: keyid
    )
}

private func rpcAlgorithmName(_ a: RpcAlgorithm) -> String {
    switch a {
    case .unspecified: return "ALGORITHM_UNSPECIFIED"
    case .ed25519: return "ALGORITHM_ED25519"
    case .secp256K1: return "ALGORITHM_SECP256K1"
    case .p256: return "ALGORITHM_P256"
    case .ed25519Webauthn: return "ALGORITHM_ED25519_WEBAUTHN"
    case .UNRECOGNIZED(let n): return "ALGORITHM_UNKNOWN(\(n))"
    }
}

private func rpcKeyFormName(_ k: RpcKeyForm) -> String {
    switch k {
    case .unspecified: return "KEY_FORM_UNSPECIFIED"
    case .rawBytes: return "KEY_FORM_RAW_BYTES"
    case .pkcs8Der: return "KEY_FORM_PKCS8_DER"
    case .opaqueHandle: return "KEY_FORM_OPAQUE_HANDLE"
    case .UNRECOGNIZED(let n): return "KEY_FORM_UNKNOWN(\(n))"
    }
}

// MARK: - Entry point

@main
struct Main {
    static func main() {
        let argv = CommandLine.arguments
        // argv[0] is the binary path.
        guard argv.count >= 2 else {
            FileHandle.standardError.write(Data((ParsedArgs.helpText + "\n").utf8))
            exit(1)
        }
        let subcommand = argv[1]
        let rest = Array(argv.dropFirst(2))

        do {
            let parsed = try ParsedArgs.parse(rest)
            switch subcommand {
            case "keygen": try runKeygen(parsed)
            case "sign": try runSign(parsed)
            case "list": try runList()
            case "delete": try runDelete(parsed)
            case "-h", "--help":
                FileHandle.standardError.write(Data((ParsedArgs.helpText + "\n").utf8))
            default:
                throw SignerError.unknownSubcommand(subcommand)
            }
        } catch let e as SignerError {
            FileHandle.standardError.write(Data("mkit-sign-se: \(e.description)\n".utf8))
            exit(1)
        } catch {
            FileHandle.standardError.write(
                Data("mkit-sign-se: unexpected error: \(error)\n".utf8))
            exit(1)
        }
    }
}
