# PasswordGate

PasswordGate is a required client-and-server Forge mod for Minecraft 1.20.1. It adds an SRP-6a password check inside Forge's login negotiation, before Minecraft creates a `ServerPlayer`, switches the connection to PLAY, sends chunks, player-list data, or world data.

## Installation

Install the built JAR in the `mods` directory on both the client and the dedicated/integrated server. Java 17 and Forge 47.x for Minecraft 1.20.1 are required. A missing or version-incompatible required network channel prevents login.

## Configuration

The world server config is `serverconfig/passwordgate-server.toml` (or the equivalent world server-config location):

```toml
enabled = true
authenticationTimeoutSeconds = 15
allowFirstJoinRegistration = true
requireOnlineModeForRegistration = true
allowUnsafeOfflineMode = false
minimumPasswordLength = 12
generatedPasswordLength = 24
maxFailedAttempts = 5
failedAttemptWindowSeconds = 300
temporaryLockoutSeconds = 300
```

Forge validates the configured ranges. The client generator length is independently configurable in `config/passwordgate-client.toml` and is at least 20 characters (>128 bits with the generator alphabet).

## First registration

With first-join registration enabled, an authenticated online-mode UUID can register during the login handshake. The server supplies a fresh 256-bit salt, receives an SRP verifier, and then immediately requires a complete SRP proof before saving it. This is trust-on-first-use. If automatic registration is disabled, an operator can grant one registration with `/passwordgate authorize <player>`; the authorization is stored atomically and consumed after successful registration.

Offline-mode automatic registration is disabled by default because an attacker can impersonate an offline UUID. Enabling `allowUnsafeOfflineMode` is an explicit risk acceptance and produces a server warning. Integrated single-player is treated as a locally authenticated profile.

## Password generation and local storage

The startup screen appears before the normal title screen. It supports hidden input, show/hide, secure generation, copy, replacement confirmation, and local reset confirmation. Generation uses `SecureRandom`, a non-ambiguous upper/lower/digit/special alphabet, and guarantees every category.

On Windows, a random 256-bit AES key is protected with the current user's DPAPI. The password is stored in a versioned AES-256-GCM record with a fresh 96-bit nonce and 128-bit tag on every write. Files are replaced atomically; owner-only POSIX permissions are applied where supported. Passwords and temporary byte/char arrays are cleared where Java permits. Java UI controls necessarily hold an immutable `String` briefly while editing.

macOS Keychain and Linux Secret Service integration are not bundled in this release. On those systems, or if DPAPI is unavailable, PasswordGate deliberately refuses persistent storage and keeps manually entered credentials only in process memory until exit. There is no plaintext, XOR, Base64-only, or machine-local hard-coded-key fallback.

## Authentication protocol and threat model

The cryptographic core uses Bouncy Castle SRP-6a, RFC 5054's 3072-bit group, SHA-256, per-account salt, fresh server ephemeral values, mutual evidence messages, and a session/transaction-bound state machine. Passwords, static password hashes, reusable proofs, and local AES ciphertext are never sent. An observed proof cannot be replayed against a fresh challenge. Packet sizes, SRP ranges, message ordering, duplicate transactions, and protocol version are checked.

The server stores only format/scheme versions, authenticated UUID, salt, verifier, registration/last-authentication timestamps, and a failure counter. `credentials.json` is bounded, parsed without Java serialization, and atomically replaced on a dedicated writer. No `.bak` containing credential material is made. The client stores only AES-GCM ciphertext plus a DPAPI-protected random AES key.

Threats covered include passive replay, a stolen server credential file (which still permits offline guessing, as every password verifier does), malformed clients, short-term brute force by UUID/IP, and login timeout/resource cleanup. PasswordGate cannot make offline-mode UUIDs authentic, protect a compromised client process, protect a copied unlocked OS account, or prevent offline guessing after server-verifier theft. The IP limiter is intentionally looser than the UUID limiter for shared IPs. Failure responses use a dummy SRP account when registration is unavailable so account existence is not directly exposed.

## Reset and commands

Operator permission level 2 is required:

```text
/passwordgate status <player>
/passwordgate reset <player>
/passwordgate revoke <player>
/passwordgate authorize <player>
/passwordgate reload
```

Reset/revoke removes only the verifier record. With automatic registration disabled, run `authorize` before the player's next registration. Commands never display passwords, salts, verifiers, or proofs.

## Build and tests

```powershell
.\gradlew.bat test
.\gradlew.bat build
.\gradlew.bat runServer
```

The tests cover generation, config bounds, SRP registration/correct/wrong password, replay and changed challenges, invalid values/packets, size limits, monotonic deadlines, rate limiting, AES-GCM corruption/nonces, atomic replacement, server serialization, format migration, and constant-time comparison behavior. For a dedicated-server smoke test, accept the generated EULA in the isolated run directory and start `runServer --args --nogui`; the main mod entry point contains no Minecraft client references and client registration is protected by `DistExecutor`.

## Porting to NeoForge 1.21.1

Cryptography, protocol records, configuration validation, rate limiting, and storage are isolated from GUI code. The Forge-specific surface is limited mainly to `AuthNetwork`, `ServerEvents`, commands, and the client bootstrap, which are the intended adapter layer for a NeoForge port.
