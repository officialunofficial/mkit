// main.swift — CLI entry for mkit-sign-se.
//
// Subcommands:
//
//     mkit-sign-se keygen --tag <label> [--require-biometric]
//     mkit-sign-se sign   --tag <label>
//     mkit-sign-se list
//     mkit-sign-se delete --tag <label>
//
// The `sign` subcommand is the one mkit drives as an external signer.
// It reads one line of JSON `{pae_base64, algorithm}` from stdin and
// writes one line of JSON `{keyid, sig_base64}` to stdout. See
// `docs/SPEC-EXTERNAL-SIGNER.md` for the wire protocol.
//
// Everything funnels through `runMain` so we can route every failure
// through a single stderr-and-exit path per SPEC §5 ("stdout SHOULD be
// empty on error").

import CryptoKit
import Foundation

// MARK: - Error type

enum SignerError: Error, CustomStringConvertible {
    case usage(String)
    case unknownSubcommand(String)
    case missingTag
    case malformedRequest(String)
    case unsupportedAlgorithm(String)
    case secureEnclaveUnavailable
    case tagNotFound(String)
    case tagAlreadyExists(String)
    case keychain(OSStatus)
    case accessControl(String)
    case biometricDeclined
    case malformedDERSignature
    case malformedPublicKey
    case requestTooLarge
    case io(String)

    var description: String {
        switch self {
        case .usage(let msg):
            return msg
        case .unknownSubcommand(let s):
            return "unknown subcommand `\(s)` (want keygen|sign|list|delete)"
        case .missingTag:
            return "missing --tag <label>"
        case .malformedRequest(let d):
            return "malformed request: \(d)"
        case .unsupportedAlgorithm(let a):
            return
                "algorithm `\(a)` not supported — Secure Enclave is P-256 only; request `\"algorithm\":\"p256\"`"
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
        case .requestTooLarge:
            return "stdin request exceeds 1 MiB"
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
            mkit-sign-se sign   --tag <label>
            mkit-sign-se list
            mkit-sign-se delete --tag <label>

        `sign` reads {pae_base64, algorithm} JSON from stdin, writes
        {keyid, sig_base64} JSON to stdout. See
        docs/SPEC-EXTERNAL-SIGNER.md for the wire protocol.

        The P-256 key lives in the Secure Enclave and is non-extractable
        by design. `--require-biometric` on keygen makes signing prompt
        for Touch ID / Face ID.
        """
}

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
    guard let tag = parsed.tag else { throw SignerError.missingTag }

    // SPEC §6: cap stdin at 1 MiB. Read up to the cap + 1 byte so we
    // can detect overflow cleanly.
    let capBytes = 1024 * 1024
    let input = try readStdinCapped(capBytes: capBytes)

    let req: SignRequest
    do {
        req = try decodeRequest(input)
    } catch {
        throw SignerError.malformedRequest("\(error)")
    }

    guard req.algorithm == "p256" else {
        // Distinct exit code for the wrong-algorithm path per the
        // task brief ("reject with exit code 2"). SPEC §5 treats any
        // non-zero uniformly today, but future protocol versions may
        // surface exit codes separately — this one is reserved.
        FileHandle.standardError.write(
            Data(
                "mkit-sign-se: \(SignerError.unsupportedAlgorithm(req.algorithm))\n".utf8))
        exit(2)
    }

    // Decode the PAE from base64.
    guard let pae = Data(base64Encoded: req.paeBase64) else {
        throw SignerError.malformedRequest("pae_base64 is not valid base64")
    }

    let key = try SecureEnclaveKey.load(tag: tag)
    let digest = SHA256.hash(data: pae)
    let sig: P256.Signing.ECDSASignature
    do {
        sig = try key.signature(for: digest)
    } catch let laError as LocalAuthenticationBridge {
        // Bridges out a user-cancel; see below.
        throw laError.asSignerError()
    } catch {
        // Anything else — surface as an IO-like error with the message
        // the CryptoKit/Security framework gave us.
        let nsErr = error as NSError
        if nsErr.domain == "com.apple.LocalAuthentication"
            || nsErr.code == -128
            || nsErr.code == errSecUserCanceled
        {
            throw SignerError.biometricDeclined
        }
        throw SignerError.io("sign: \(error.localizedDescription)")
    }

    // `rawRepresentation` on P256.Signing.ECDSASignature is the
    // 64-byte compact `r || s`. Per the task brief, this is the right
    // accessor — do NOT use `derRepresentation`.
    let compact = sig.rawRepresentation
    precondition(compact.count == 64, "compact ECDSA signature must be 64 bytes")

    let keyid = try key.keyidString()
    let response = SignResponse(
        keyid: keyid,
        sigBase64: compact.base64EncodedString()
    )
    let line = try encodeResponseLine(response)
    FileHandle.standardOutput.write(Data((line + "\n").utf8))
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

// MARK: - stdin helpers

private func readStdinCapped(capBytes: Int) throws -> Data {
    let handle = FileHandle.standardInput
    var out = Data()
    while out.count <= capBytes {
        let chunk = handle.availableData
        if chunk.isEmpty { break }
        out.append(chunk)
    }
    if out.count > capBytes {
        throw SignerError.requestTooLarge
    }
    return out
}

// MARK: - LocalAuthentication bridge

/// Tiny adapter so we can surface `LAError.userCancel` distinctly from
/// other CryptoKit failures without importing LAError comparisons at
/// every catch site.
struct LocalAuthenticationBridge: Error {
    let userCancelled: Bool
    func asSignerError() -> SignerError {
        userCancelled ? .biometricDeclined : .io("local authentication failed")
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
