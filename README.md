# PasswordGate

PasswordGate is a required client-and-server mod for Minecraft 1.21.1 and NeoForge 21.1. It performs mutual SRP-6a password authentication as a NeoForge configuration task, before the connection can finish configuration or create/place a `ServerPlayer`.

## Requirements and installation

- Minecraft 1.21.1
- NeoForge 21.1.235 or newer compatible 21.1 build
- Java 21
- the same PasswordGate protocol version on client and server

Build with `./gradlew build` (`.\gradlew.bat build` on Windows) and copy `build/libs/passwordgate-1.0.0.jar` to the `mods` directory of both client and server. A Forge 1.20.1 JAR cannot be used with NeoForge, and this NeoForge JAR cannot be used with Forge.

## Configuration

The world-specific server file is `<world>/serverconfig/passwordgate-server.toml`:

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

Ranges are 5..120 seconds for the timeout, 8..256 for minimum password length, 21..256 for generated length, 1..100 attempts, and 10..86400 seconds for failure window/lockout. The client generator length is in `config/passwordgate-client.toml`. A legacy value of 20 is corrected to 21 because the actual 70-character alphabet needs 21 characters for a direct entropy floor above 128 bits.

NeoForge watches configuration files. `/passwordgate reload` applies the current validated snapshot to new connections and safely closes unfinished authentication sessions. `enabled` affects whether new configuration tasks are added. Timeout, registration policy, minimum length and limiter values affect new sessions; existing authenticated players are never retroactively changed.

## Authentication and security model

The unchanged cryptographic implementation is Bouncy Castle 1.78.1 SRP-6a using RFC 5054's 3072-bit group, SHA-256, a fresh server ephemeral/challenge, 256-bit account salt and mutual M1/M2 evidence. The server stores a verifier, never a password. The wire never carries a password, static password hash or reusable proof.

Every connection has a random session UUID and strictly increasing sequence. The state machine accepts exactly `REGISTER_REQUEST -> REGISTER_SUBMIT -> CHALLENGE -> CLIENT_PROOF -> SERVER_PROOF -> ACK` for registration, or the challenge suffix for an existing account. Wrong-session, replayed, duplicate, malformed, oversized and out-of-order messages disconnect before play. Only one unfinished session per authenticated UUID is allowed.

The configuration task is completed only after M2 is checked by the client, ACK is received, and the server record is atomically persisted. Vanilla creates and places the player only after all configuration tasks and `ServerboundFinishConfigurationPacket`; therefore an unauthenticated connection has no `ServerPlayer`, world presence, chunks, Tab entry or play payloads. SRP and client registration calculations run on dedicated crypto workers; state transitions return to the game executor. The timeout uses a daemon `ScheduledExecutorService`, starts on the first PasswordGate challenge/request, is independent of server ticks, and is cancelled on success, disconnect, reload and shutdown.

Rate limiting remains keyed by UUID and address. Unknown accounts use a generated dummy SRP record when registration is not allowed, reducing account-existence leakage. PasswordGate protects against passive proof replay and online guessing; theft of a verifier database still permits offline guessing, as with any password verifier.

## Online/offline mode

With `online-mode=true`, registration uses the authenticated Mojang UUID. Automatic first registration is enabled by default only for authenticated online profiles or integrated single-player. A dedicated offline-mode server logs a prominent warning and disables automatic first registration unless `allowUnsafeOfflineMode=true` explicitly accepts UUID impersonation risk. PasswordGate cannot make offline UUIDs trustworthy.

## Client screen and storage

At startup PasswordGate first attempts to decrypt the protected local credential. When a non-empty password is found, it is loaded directly into process memory and the normal title screen is shown without opening PasswordGate. The PasswordGate screen appears only when the credential is absent, unreadable or damaged. It supports hidden/show input, Enter confirmation, keyboard focus navigation, generation, clipboard copy, protected-password replacement and reset, localization and responsive layout after resize.

The generator uses `SecureRandom` and a 70-character unambiguous alphabet. The minimum generated length is 21 characters (>128.7 bits from the alphabet alone); the default 24 exceeds 147 bits. Uppercase, lowercase, digit and special categories are all enforced.

On Windows, a random 256-bit AES key is protected by the current user's DPAPI and the password is AES-256-GCM encrypted with a fresh 96-bit nonce and 128-bit tag. No plaintext, XOR, Base64-only, hard-coded-key or machine-ID fallback exists. If system secret storage is unavailable, persistent storage is refused; a manually entered password may remain only in process memory for that run. Java GUI widgets necessarily hold an immutable `String` while editing.

## Commands

Permission level 2 is required:

```text
/passwordgate status <player>
/passwordgate reset <player>
/passwordgate revoke <player>
/passwordgate authorize <player>
/passwordgate reload
```

`reset` and `revoke` atomically remove the verifier. `authorize` grants one stored first-registration authorization when automatic registration is disabled. Messages never expose salt, verifier, proof or password.

## Build and verification

```powershell
.\gradlew.bat test
.\gradlew.bat build
.\gradlew.bat runClient
.\gradlew.bat runServer
```

Unit tests cover SRP success/wrong-password/replay, packet bounds and corruption, sequence encoding, rate limits, timeout helpers, generator entropy constraints, AES-GCM integrity/fresh nonces, real Forge client fixture loading, server format 0/1 loading, future-version rejection and atomic repository writes. The development client and dedicated server have smoke-launched on Java 21; detailed port and manual handshake cases are in [PORTING.md](PORTING.md).

## Known limitations

- DPAPI persistence is Windows-only; macOS Keychain and Linux Secret Service are not bundled.
- Registry/configuration synchronization inherent to Minecraft's configuration phase can occur before the PasswordGate task, but no player/world/chunk/Tab/play data is produced before authentication.
- End-to-end hostile-client scenarios require two real game processes and are listed as manual checks in `PORTING.md`.
