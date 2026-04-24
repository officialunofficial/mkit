// SecureEnclaveKey.swift — thin wrapper around
// `CryptoKit.SecureEnclave.P256.Signing.PrivateKey` with Keychain
// persistence under `kSecAttrAccount = <tag>`.
//
// Design notes:
//
// * Secure Enclave keys are *non-extractable* — the private scalar
//   never leaves the SEP. We persist the opaque `dataRepresentation`
//   blob (an encrypted reference only the SEP on this device can
//   open), associated with a user-chosen tag, so the `sign`
//   subcommand can reload it later.
// * We store under `kSecClassGenericPassword` rather than
//   `kSecClassKey` because the `dataRepresentation` blob is NOT an
//   actual SecKey — it is an opaque handle that only CryptoKit can
//   reconstitute. Generic-password storage is the correct keychain
//   class for arbitrary per-tag opaque blobs and sidesteps the
//   `kSecAttrKeyType` indexing surprises `kSecClassKey` brings for
//   non-SecKey payloads. `kSecAttrService` is a stable string shared
//   across all our items; `kSecAttrAccount` holds the tag.
// * Biometric gating is optional on keygen: if requested, we wire a
//   `SecAccessControl` with `.biometryCurrentSet`. Default is no
//   gating so the signer is usable in CI / automation.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// Stable `kSecAttrService` value used for every item this binary
/// owns. Distinct enough to avoid colliding with user-added generic
/// keychain entries.
private let kMkitSignSeService = "dev.mkit.mkit-sign-se"

enum SecureEnclaveKey {

    /// True if the SEP is usable on this device. Intel Macs without T2
    /// and some sandboxed environments return `false`; in that case we
    /// surface a clean error rather than silently falling back to a
    /// software key.
    static var isAvailable: Bool {
        SecureEnclave.isAvailable
    }

    // MARK: - keygen

    /// Create a new Secure Enclave P-256 key and persist its data
    /// representation in the login keychain under `tag`. Returns the
    /// freshly minted key.
    ///
    /// - Parameters:
    ///   - tag: Opaque label stored as `kSecAttrAccount`. UTF-8
    ///     bytes. Pick something stable and unique to your app.
    ///   - requireBiometric: If true, signing will prompt for
    ///     Touch ID / Face ID the first time per LAContext (and every
    ///     time if the user re-locks). Adds
    ///     `.biometryCurrentSet` to the access control — if the user
    ///     enrolls a new biometric later, the key becomes unusable.
    static func create(tag: String, requireBiometric: Bool) throws
        -> SecureEnclave.P256.Signing.PrivateKey
    {
        guard isAvailable else { throw SignerError.secureEnclaveUnavailable }
        guard try findBlob(tag: tag) == nil else {
            throw SignerError.tagAlreadyExists(tag)
        }

        let key: SecureEnclave.P256.Signing.PrivateKey
        if requireBiometric {
            var accessError: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage, .biometryCurrentSet],
                &accessError
            ) else {
                let err = accessError?.takeRetainedValue()
                throw SignerError.accessControl(err.map { ($0 as Error).localizedDescription }
                    ?? "unknown")
            }
            key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        } else {
            key = try SecureEnclave.P256.Signing.PrivateKey()
        }

        try persist(blob: key.dataRepresentation, tag: tag)
        return key
    }

    // MARK: - load

    /// Load a previously-persisted SEP key by tag.
    static func load(tag: String) throws -> SecureEnclave.P256.Signing.PrivateKey {
        guard isAvailable else { throw SignerError.secureEnclaveUnavailable }
        guard let blob = try findBlob(tag: tag) else {
            throw SignerError.tagNotFound(tag)
        }
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
    }

    // MARK: - list

    /// List every tag this binary has stored. Each entry is `(tag,
    /// compressed-pubkey-hex)`.
    static func list() throws -> [(tag: String, pubkeyHex: String)] {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: kMkitSignSeService,
            kSecReturnAttributes: true,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitAll,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return []
        }
        guard status == errSecSuccess, let items = result as? [[CFString: Any]] else {
            throw SignerError.keychain(status)
        }
        var out: [(String, String)] = []
        for item in items {
            guard
                let tag = item[kSecAttrAccount] as? String,
                let blob = item[kSecValueData] as? Data
            else { continue }
            if let key = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob) {
                let pk = try? compressSEC1FromRaw(key.publicKey.rawRepresentation)
                out.append((tag, pk.map(hexLower) ?? "<error>"))
            }
        }
        return out
    }

    // MARK: - delete

    static func delete(tag: String) throws {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: kMkitSignSeService,
            kSecAttrAccount: tag,
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecItemNotFound {
            throw SignerError.tagNotFound(tag)
        }
        guard status == errSecSuccess else {
            throw SignerError.keychain(status)
        }
    }

    // MARK: - internals

    private static func persist(blob: Data, tag: String) throws {
        let add: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: kMkitSignSeService,
            kSecAttrAccount: tag,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData: blob,
        ]
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw SignerError.keychain(status)
        }
    }

    private static func findBlob(tag: String) throws -> Data? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: kMkitSignSeService,
            kSecAttrAccount: tag,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw SignerError.keychain(status)
        }
        return result as? Data
    }
}

// MARK: - Pubkey helpers on the SEP key

extension SecureEnclave.P256.Signing.PrivateKey {

    /// 33-byte SEC1-compressed pubkey — the form we use as the keyid.
    func compressedPublicKey() throws -> Data {
        try compressSEC1FromRaw(publicKey.rawRepresentation)
    }

    /// `p256:<66-hex>` keyid string.
    func keyidString() throws -> String {
        "p256:" + hexLower(try compressedPublicKey())
    }
}
