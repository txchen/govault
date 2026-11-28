# GoVault Architecture and MVP Design

## Goal

Deliver a fast, low-memory, zero-CGO native desktop client for self-hosted Vaultwarden (Bitwarden-compatible) servers, targeting macOS (primary development host, with Touch ID unlock) and Linux desktop, built on a UI-agnostic Go core (`vaultcore`) and an NSGo (`nsgo.dev`) native-view frontend.

## Non-goals

- **Mobile apps (iOS / Android)**: Official Bitwarden mobile apps are already native Swift/Kotlin + Rust SDK with deep OS AutoFill and Passkey integration. GoVault focuses on replacing the heavy Electron desktop client.
- **Browser extension replacement**: Official browser extensions remain the recommended tool for in-browser autofill; both connect to the same Vaultwarden server.
- **OS-level FIDO2/Passkey provider & SSH Agent (in MVP)**: Deferred out of MVP; SSH Agent can be considered in a later phase.
- **Enterprise-only features**: Key Connector, Trusted Device Encryption, billing, directory connector, and Vaultwarden admin panel.
- **Embedded SQLite database**: Explicitly excluded to keep zero-CGO cross-compilation, minimal binary size, and zero plaintext on disk.

## Scope and Constraints

- **Server compatibility**: Self-hosted Vaultwarden (Bitwarden API compatible).
- **Development host & platforms**: Developed primarily on macOS; targets macOS and Linux desktop (Windows remains feasible via the same zero-CGO build).
- **Performance & efficiency**: Fast startup/search and minimal CPU and memory footprint.
- **macOS Touch ID**: Fingerprint (Touch ID) unlock supported on macOS.
- **Storage**: No SQLite database; atomic encrypted JSON snapshots on disk and in-memory search.
- **Authentication**: Email + master password and browser-based OAuth2 + PKCE (`S256`) SSO (via a `http://localhost:8065..8070` loopback callback, requiring Vaultwarden 1.37.4+ or Bitwarden Cloud/Self-hosted for desktop, followed by master password unlock for accounts with a master password; Key Connector and Trusted Device Encryption are not supported yet), plus two-step login with an authenticator app (provider `0`), email codes (provider `1`) or a YubiKey OTP (provider `3`, the 44-character modhex code the key types, checked for shape before it is sent) and an optional remembered device. When several are offered, the default follows Bitwarden's priority: YubiKey, then authenticator, then email. Other providers (WebAuthn, Duo) show a clear unsupported message. Bitwarden's new device verification is supported too: an account without two-step login signing in from a device the server does not know is asked for a code emailed to it, with Resend Code (`api.NewDeviceVerificationRequiredError`, `newDeviceOtp`).
- **Vault scope**: Personal vault (Login, Secure Note, Card, Identity, Folders, Trash, TOTP codes, Password/Passphrase generator) and organization items in shared collections. Attachments and Sends are still planned.
- **macOS concealed clipboard**: Included in MVP (`org.nspasteboard.ConcealedType` and `org.nspasteboard.TransientType`) so clipboard managers do not record copied secrets.
- **No Quick Access panel**: The floating panel and global hotkey were dropped; the main window search (`Cmd+F`) covers that workflow.
- **UI framework**: NSGo (`nsgo.dev`) native-view engine, kept strictly isolated from `vaultcore` so the core remains reusable across any UI layer.

### Engineering Resource Targets

- Cold start to unlock screen: `< 300 ms` on Apple Silicon macOS.
- Idle tray-resident memory (locked / window closed): `< 30 MB` physical footprint on macOS (`footprint` / Activity Monitor Memory) / RSS on Linux (note: macOS `ps` RSS includes shared AppKit/system framework mappings).
- Active unlocked window memory (1,000–3,000 ciphers): `< 70 MB` physical footprint on macOS / RSS on Linux (excluding transient Argon2id spike, which is reclaimed).
- Idle CPU usage (window hidden or static): `~0.0%` (zero background UI timers).

## Design

### 1. High-Level Layered Architecture

Strict separation ensures `vaultcore` has **zero imports** of `nsgo` or any GUI package:

```text
+-------------------------------------------------------------------+
|  cmd/govault  (NSGo Desktop App Shell)                            |
|  - Optional menu bar icon, Main Window, in-app updates            |
|  - Signals & Views (Unlock, Vault SplitView, Editor, Generator)   |
|  - Adapters: SecretsAdapter (cx.Secrets), BiometricAdapter,       |
|              ClipboardAdapter (with concealed/auto-clear),        |
|              Notification/Lifecycle hooks                         |
+-------------------------------+-----------------------------------+
                                | Go interfaces & domain structs
                                v
+-------------------------------------------------------------------+
|  internal/vaultcore  (Pure Go, Zero CGO, Zero UI Dependencies)    |
|  - crypto/     : KDF (PBKDF2, Argon2id), HKDF, AES-256-CBC-HMAC,  |
|                  RSA-OAEP, EncString parser/encoder, zeroize      |
|  - api/        : Prelogin, OAuth2 token + refresh, /api/sync,     |
|                  cipher/folder CRUD, revision-date, icons         |
|  - realtime/   : SignalR/MessagePack WebSocket (/notifications/hub)|
|  - store/      : Store interface + atomic encrypted JSON file     |
|  - state/      : Lock/Unlock state machine, in-memory decrypted   |
|                  vault, fuzzy search index, memory wipe on lock   |
|  - totp/       : RFC 6238 / otpauth:// URI parser & generator     |
|  - gen/        : CSPRNG password & EFF-style passphrase generator |
+-------------------------------------------------------------------+
```

### 2. Cryptography and Key Hierarchy (`internal/vaultcore/crypto`)

Follows the Bitwarden/Vaultwarden cryptographic specification (see [`vaultcore-spec.md`](vaultcore-spec.md) for full details and verified test vectors):

1. **Prelogin**: `POST /identity/accounts/prelogin` returns KDF type (`0` = PBKDF2-SHA256, `1` = Argon2id) and parameters.
2. **Master Key Derivation**:
   - Email is normalized (`strings.ToLower(strings.TrimSpace(email))`).
   - `PBKDF2`: `PBKDF2-HMAC-SHA256(password, email, iterations, 32)`.
   - `Argon2id`: `Argon2id(password, SHA256(email), time=iterations, memory=kdfMemory*1024 KiB, threads=kdfParallelism, keyLen=32)`.
   - **Memory reclamation**: After Argon2id completes and sensitive temporary buffers are zeroed, call `debug.FreeOSMemory()` so the working set is returned to the OS promptly.
3. **Master Password Hash (for login only)**:
   - `Base64(PBKDF2-HMAC-SHA256(masterKey, password, 1, 32))` sent to `/identity/connect/token`.
4. **Stretched Master Key**:
   - `encKey = HKDF-Expand(SHA256, masterKey, "enc", 32)` (no HKDF-Extract)
   - `macKey = HKDF-Expand(SHA256, masterKey, "mac", 32)`
5. **Protected Symmetric User Key**:
   - Server returns `Key` (EncString) in token/sync response; decrypting yields the 64-byte **User Key** (`userEncKey` 32B + `userMacKey` 32B).
   - **Invariant**: Never store the raw master password on disk or in Keychain. Only the decrypted User Key (and OAuth refresh token) is stored in Keychain when Touch ID unlock is enabled.
6. **CipherString (`EncString`) & Per-Cipher Key**:
   - Standard Type 2 (`AesCbc256_HmacSha256_B64`): verify HMAC-SHA256 (`MAC(iv || ct, macKey)`) in constant time before AES-256-CBC decryption.
   - If a cipher has a non-empty `cipher.key`, unwrap that 64-byte per-cipher symmetric key first and use it to decrypt the cipher's fields.
   - **Organizations**: `profile.privateKey` (Type 2, PKCS#8) is decrypted with the User Key, then each enabled `organization.key` (RSA-OAEP Types 3–6, SHA-256 or SHA-1) is unwrapped into a 64-byte org key held only in memory. Org ciphers and collection names decrypt with that key (per-cipher keys are wrapped with it), and edits re-encrypt with it while keeping `organizationId` and `collectionIds`.
7. **Memory Hygiene**:
   - Overwrite sensitive `[]byte` key material on lock, logout, sleep, and session timeout.

### 3. macOS Touch ID Unlock & Lock Lifecycle

1. **Enrollment (opt-in in Settings after master-password unlock)**:
   - Check `cx.BiometricAvailability` returns `core.BiometricFingerprint` (Touch ID) or `core.BiometricFace`.
   - Prompt once with `cx.AuthenticateBiometric("Enable Touch ID for GoVault", ...)`.
   - On `core.BiometricSuccess`, store the 64-byte User Key (base64) in `cx.Secrets()` under `"userkey:" + accountID`.
2. **Unlock Flow**:
   - Run `cx.AuthenticateBiometric("Unlock GoVault", ...)` -> on success, fetch `userkey:<id>` off the UI goroutine via `cx.Secrets().Get(...)`, load encrypted snapshot from disk, decrypt into memory, and transition state to `Unlocked`.
   - If Touch ID fails, cancels, or is unavailable, seamlessly fall back to Master Password input.
3. **Keychain Enforcement Note (Verified)**:
   - Verified in `nsgo-dev/nsgo` (`internal/platform/apple/secrets.go` @ `1099393de136`): with empty `AccessGroup`, `core.Secrets` uses the macOS login Keychain (requires no entitlements and works on ad-hoc dev builds; `Accessible` only applies when `AccessGroup` is set on the Data Protection Keychain, which requires a signed app with `keychain-access-groups`). It does **not** set `SecAccessControl` (`biometryCurrentSet`), relying on app-level `LAContext` Touch ID gating (`apple/biometric.go`). Acceptable for MVP; hardware-enforced `SecAccessControl` can be added in Phase 2 for signed release builds.
   - **Hardware-enforced key with fallback (`cmd/govault/biokeychain*.go`)**: `BiometricSecretStore` wraps `core.Secrets` and handles only `userkey:<accountID>`. On save it first tries the Data Protection Keychain (`kSecUseDataProtectionKeychain`) with a `SecAccessControl` of `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` + `kSecAccessControlBiometryCurrentSet`, through `purego` and `Security.framework`. If that succeeds the login Keychain copy is deleted and unlock reads the item directly, so macOS shows its own Touch ID prompt and GoVault skips `LAContext` (no double prompt). If macOS answers `errSecMissingEntitlement` (`-34018`) or the access control cannot be created, the key goes to the login Keychain and unlock keeps the `LAContext` gate. Delete clears both stores. Settings → Security shows which protection is active.
   - **Verified behavior** (macOS 27.2.1, arm64, `SecAccessControlCreateWithFlags` succeeds in every case):

     | Binary | `SecItemAdd` (Data Protection + biometry) | `SecItemCopyMatching` | `SecItemDelete` |
     |---|---|---|---|
     | Ad-hoc (Go linker signature) | `-34018` | `-25300` | `-34018` |
     | Developer ID Application + hardened runtime, no profile | `-34018` | `-25300` | `-34018` |
     | Developer ID + `keychain-access-groups` entitlement, no profile | process killed by AMFI ("restricted entitlements") | — | — |

     The login Keychain round trip through the same bindings succeeds for both binaries. The hardware path therefore needs a build with an embedded provisioning profile that grants `keychain-access-groups` (for example a Mac App Store or profile-signed build). Current Developer ID releases use the app-gated login Keychain path, and the code switches to the hardware path automatically when the entitlement is present. Rerun the probe with `GOVAULT_KEYCHAIN_PROBE=1 go test -run Probe -v ./cmd/govault`, or build it with `go test -c` and sign it first.
4. **Lock Triggers**:
   - Manual lock (`Cmd+L` / menu bar), configurable idle timeout (default 15 minutes), and, on macOS, system sleep or screen lock (`NSWorkspaceWillSleepNotification` and `com.apple.screenIsLocked`, observed via `purego/objc`; on by default, toggle in Settings).
   - On lock: zero in-memory User Key, org keys and decrypted cipher structs, stop all UI timers, clear UI signals and release Secure Event Input.

### 4. Storage, Sync, and Real-Time Updates

1. **Local Storage (Zero SQLite, Zero Plaintext on Disk)**:
   - **Encrypted Vault Snapshot**: `cx.DataDir()/vault_<accountID>.enc.json` — stores the raw encrypted `/api/sync` response payload plus local metadata (`lastSyncAt`, `revisionDate`, `serverURL`, `email`, `kdfParams`). Written atomically via temp file + `fsync` + `os.Rename` with `0600` permissions.
   - **Secrets (`cx.Secrets()`)**: OAuth `refresh_token` and (if Touch ID enabled) `user_key`.
   - **Preferences (`cx.Storage()`)**: Non-sensitive UI settings via `core.NewPersisted`.
   - **Favicon Cache**: icons from `<server>/icons/<domain>/icon.png`, stored in `cx.CacheDir()/icons/<domain>.png` plus a 256-entry memory LRU and a negative cache; fetched by 4 bounded workers. The "Show website icons" toggle disables all requests, and "Clear Icon Cache" removes them.
2. **Sync Flow**:
   - On unlock: immediately decrypt local `vault_<accountID>.enc.json` so the UI is usable offline in `< 50 ms`.
   - In background: call `GET /api/accounts/revision-date`; only fetch full `GET /api/sync` if the server revision date is newer (or on manual sync `Cmd+R`).
   - Transparent access-token refresh via `POST /identity/connect/token` (`grant_type=refresh_token`).
3. **Real-Time Push (`internal/vaultcore/realtime`)**:
   - Connects to `wss://<host>/notifications/hub?access_token=<token>` using SignalR handshake + varint-framed MessagePack (matching Vaultwarden `src/api/notifications.rs`).
   - Handles cipher/folder/vault sync triggers and `LogOut` pushes with exponential backoff reconnect.

### 5. UI/UX & Resource-Efficiency Design (`cmd/govault`)

See [`ui-and-state-machine.md`](ui-and-state-machine.md) for complete wireframes, state machines, keyboard shortcuts, and NSGo signal wiring:

- **Main Window (`desktop.OpenWindow`)**: resizable 3-pane layout (sidebar, virtualized item list, detail/editor) with draggable dividers whose widths persist. The sidebar shows categories, folders and, when the vault has any, a collapsible Collections section.
- **Optional menu bar icon (`desktop.NewTray`)**: on by default; closing the main window keeps the app alive in the menu bar. With the icon off, the Dock icon stays visible; menu-bar-only mode uses `desktop.SetDockVisible(false)`.
- **In-app updates**: NSGo's Sparkle-style updater reads a signed (Ed25519) appcast from the GitHub release and installs updates automatically.
- **macOS Concealed Clipboard**: Dedicated zero-CGO `clipboard_darwin.go` helper via `purego/objc` setting `org.nspasteboard.ConcealedType` and `org.nspasteboard.TransientType` and checking `NSPasteboard.changeCount` before auto-clearing.
- **CPU & Memory Safeguards**: Visibility-gated 1s TOTP ticker (stopped when hidden/locked/non-TOTP), single `time.AfterFunc` idle lock timer, and `debug.FreeOSMemory()` post-Argon2id.

### 6. Phased Roadmap

| Phase | Scope |
| --- | --- |
| **Phase 0: Feasibility Spike** | macOS NSGo smoke test measuring cold-start time, idle/active RSS & CPU, Touch ID (`core.Biometric`), Keychain (`core.Secrets`), `desktop.OpenPanel`, and `clipboard_darwin.go`. |
| **Phase 1: MVP** | `vaultcore` (Prelogin, PBKDF2 & Argon2id, OAuth2 email+password login, AES-256-CBC-HMAC, `/api/sync`, encrypted JSON cache, personal Login/Note/Card/Identity CRUD, Folders, Trash, TOTP code generation, Password/Passphrase Generator, SignalR WS sync) + NSGo Main Window + macOS Touch ID + Auto-clearing concealed clipboard + macOS & Linux builds. |
| **Phase 2: Daily-Driver Polish** | Shipped in 0.2.x: 2FA login (authenticator and email), organizations and shared collections, favicon cache with privacy toggle, lock on macOS sleep/screen lock, signed auto-update feed. Remaining: WebAuthn 2FA, attachments, Bitwarden Send, multi-account switching, Linux Secret Service + tray polish. |
| **Phase 3: Optional Power Features** | Local Vault Health / weak-password report, Optional SSH Agent (`ssh-agent` socket serving SSH Key ciphers), Windows packaging. |

### 7. Target Repository Layout

```text
govault/
├── go.mod
├── docs/
│   ├── architecture.md
│   ├── vaultcore-spec.md
│   ├── ui-and-state-machine.md
│   └── research/
│       └── official-client-and-protocol.md
├── cmd/
│   ├── govault/
│   │   ├── nsgo.yaml           # NSGo build manifest (co-located with package main for `go tool nsgo build ./cmd/govault`)
│   │   ├── locales/            # UI message catalogs: en.yaml source, generated catalog_gen.go (see i18n.md)
│   │   ├── main.go
│   │   ├── app.go              # menu bar icon, window lifecycle, updates
│   │   ├── adapters.go         # NSGo Secrets/Biometric/Clipboard bridges
│   │   ├── clipboard_darwin.go # concealed NSPasteboard helper (purego/objc)
│   │   ├── secureinput_darwin.go # Secure Event Input release (purego)
│   │   ├── sleeplock_darwin.go # sleep/screen-lock observers (purego/objc)
│   │   └── ui/                 # Login/2FA, Lock, Vault, Editor, Generator, Settings, favicons
│   └── gv/                     # bw-compatible CLI (see cli-design.md)
├── internal/
│   ├── cli/                    # gv commands, parsing, prompts and bw-shaped output
│   ├── fakeserver/             # Bitwarden-compatible test server
│   └── vaultcore/
│       ├── crypto/             # KDF, HKDF, EncString, AES-CBC-HMAC, RSA, zeroize
│       ├── api/                # HTTP client, auth, sync, cipher/folder endpoints
│       ├── realtime/           # SignalR MessagePack WebSocket client
│       ├── store/              # Store interface + atomic encrypted JSON store
│       ├── state/              # Vault state machine, in-memory index, fuzzy search
│       ├── totp/               # RFC 6238 TOTP
│       ├── gen/                # Password & passphrase generator, fingerprint phrases
│       ├── profile/            # gv's multi-process sign-in, sessions and cache
│       ├── keyring/            # OS credential stores for gv
│       └── privatefile/        # user-only files and atomic writes
└── assets/
    └── Icon.png
```

## Acceptance Criteria

- [ ] `vaultcore` compiles with `CGO_ENABLED=0` and passes all 10 unit test vector suites in [`vaultcore-spec.md`](vaultcore-spec.md).
- [ ] Integration test against a local Vaultwarden instance succeeds for email+password login, `/api/sync`, cipher create/edit/soft-delete/restore, folder CRUD, and WebSocket push update.
- [ ] On macOS, Touch ID unlocks the vault without re-entering the master password, and locking clears decrypted keys/ciphers from memory.
- [ ] On macOS, copied secrets carry `org.nspasteboard.ConcealedType` and `org.nspasteboard.TransientType` pasteboard markers and auto-clear after the configured timeout.
- [ ] Resource targets verified on macOS: idle tray memory `< 30 MB` physical footprint (RSS on Linux), active window `< 70 MB` physical footprint (RSS on Linux), idle CPU `~0%`.
- [ ] `go tool nsgo build ./cmd/govault` from macOS produces runnable macOS (`.app`/`.dmg`) and Linux (`.AppImage`/`.deb`) packages with `CGO_ENABLED=0`.

## Risks

- **NSGo API churn & Linux desktop parity**: NSGo is pre-1.0; tray behavior on Linux (especially Wayland) may have edge cases. *Mitigation*: Isolate all NSGo calls in `cmd/govault`, keep `vaultcore` 100% decoupled, and validate X11/Wayland behavior early.
- **Cryptography correctness bugs**: Subtle mistakes in MAC verification, padding, or key stretching can corrupt vault items on write. *Mitigation*: Test against official Bitwarden SDK test vectors and run write tests against a throwaway local Vaultwarden Docker instance first.
- **Keychain vs hardware-enforced Touch ID**: Without `SecAccessControl`, another process running as the same user with Keychain access could read the login Keychain item. *Mitigation*: `BiometricSecretStore` uses a `SecAccessControl` (`biometryCurrentSet`) item in the Data Protection Keychain whenever the build is entitled to it, and Settings shows when the app-gated fallback is in use.
- **Argon2id memory retention**: Go's GC may retain 64 MiB after Argon2id unlock. *Mitigation*: Explicitly zero buffers and call `debug.FreeOSMemory()` post-derivation.

## Related Documents

- [`vaultcore` Interface, Protocol, and Test Vector Specification](vaultcore-spec.md)
- [UI Wireframes, State Machine, and NSGo Signal Architecture](ui-and-state-machine.md)
- [Official Bitwarden Desktop Client, Vaultwarden Protocol, and NSGo Research](research/official-client-and-protocol.md)
