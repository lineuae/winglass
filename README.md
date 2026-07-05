<h1 align="center">winglass</h1>

<p align="center">
  <em>A Windows process manager that tells you who actually signed the thing.</em>
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#what-it-shows">What it shows</a> ·
  <a href="#anti-spoof-guarantee">Anti-spoof guarantee</a> ·
  <a href="#keyboard">Keyboard</a> ·
  <a href="#building-from-source">Building from source</a>
</p>

<hr>

Task Manager tells you a process is called `svchost.exe` and lets you kill
it. Process Explorer tells you a bit more, wrapped in a UI that hasn't been
touched since 2005. Neither one tells you whether the `svchost.exe` you're
looking at was actually signed by Microsoft — or whether it's a malicious
binary someone renamed to blend in.

**winglass reads the Authenticode signature on every file it shows you** —
executables, DLLs, and the catalog fallbacks that cover most Windows system
files. A process is only marked as Windows-signed if its signer's Common
Name literally starts with "Microsoft Windows". You cannot forge that
without Microsoft's private key.

Everything else — full command lines, loaded DLLs, per-process network
sockets with reverse DNS, disk I/O throughput, CPU/memory sparklines,
SHA-256 hashes, environment variables, PPL protection labels — is built
on top of that trust primitive.

Single binary. No runtime. No cloud. No telemetry.

## Install

Grab the latest release from **[Releases](../../releases)**. Two options,
same app inside:

| File | Size | What it does |
|------|------|--------------|
| `winglass_*_x64_en-US.msi` | ~3 MB | Standard Windows Installer. Adds a Start-menu entry, registers with Programs and Features, handles uninstall. |
| `winglass_*_x64-setup.exe` | ~2 MB | NSIS installer. Same result, smaller download. |
| `winglass.exe` | ~8 MB | Portable. Put it wherever, double-click, no install. Nothing else on your system changes. |

**Windows 10 (1809+) or Windows 11.** Requires WebView2, which is
preinstalled on Windows 11 and shipped with recent Edge on Windows 10.

### Elevated vs unelevated

Most of winglass works fine without admin. Two things get better with
elevation:

- **DLL enumeration** on services running as `LocalSystem` succeeds where
  it would otherwise return `access denied`.
- **Executable paths for privileged services** — but even without admin,
  winglass has a three-tier path resolution chain that reaches most
  processes via `NtQuerySystemInformation`. Only the true PPL processes
  (Windows Defender, csrss, LSASS with RunAsPPL) refuse everything.

PPL processes are a hard Windows security boundary; only a signed kernel
driver crosses it, and shipping one is out of scope. winglass labels them
`protected process (PPL, Antimalware)` in yellow so you know the wall is
by design, not a bug.

## What it shows

### Signature-first process table

Every row has a signature dot and a signer column. Windows OS-signed
processes get their name rendered in green. Signed-but-not-Windows
processes stay neutral. Unsigned or verify-failed are red.

The header keeps a live count of unsigned processes visible at a glance.

### Detail panel

Click a row and a right-side panel slides in with everything winglass
knows about that PID. It updates once per second while it's open.

**Sparklines** — 60-second CPU and memory history rendered as inline SVG.
CPU on a fixed 0-100% scale so a saturated core stands out; memory
auto-scales to its own recent peak so idle drifts stay readable.

**Signature block** — icon plus signer CN plus the "Windows OS" flag or
"Signed" for third-party. If the file is signed via a Windows catalog
(the `.cat` files in `System32\CatRoot\`), the badge shows the catalog's
signer — that's the trust anchor the file is actually resting on.

**Executable path** with its full **SHA-256 digest** underneath. Both are
selectable. The hash is useful for reproducibility checks, forensic
comparison against a known-good build, or feeding to VirusTotal.

**Command line** — not truncated. Chromium renderers routinely have 30+
line command lines full of feature flags; Opera's `--with-feature:...`
list can wrap five times. It's all there.

**User, uptime, parent chain** — up to three parents deep with names and
PIDs, so you can see whether that suspicious PowerShell was spawned by
Office or by an ordinary shell.

**I/O tiles** — three columns: read, write, other. Current MB/s plus
lifetime cumulative bytes. Backed by `GetProcessIoCounters`.

**Network sockets** — every open TCP and UDP endpoint owned by this
process. TCP state colored (`ESTABLISHED` green, `LISTEN` yellow). Remote
IPs get reverse DNS from the OS resolver; hostnames render in magenta
with the original IP in gray for verification.

**DLLs** — every module loaded into the process, one per line, each with
its own signature dot and signer name. The section header shows the
loaded count plus the unsigned count in red if anything failed
verification. On PPL processes, this section shows the protection label
in yellow instead.

**Environment** — collapsible. Click to expand. Every `KEY=VALUE` the
process inherited or set, useful for debugging why something behaves
differently in this shell than in that one.

## Anti-spoof guarantee

The point of grounding trust in the certificate — not the path, not the
name — is that it survives adversarial conditions.

Copy `winglass.exe` to `svchost.exe` and drop it in
`C:\Windows\System32\`. Task Manager will happily show it as
`svchost.exe`. Process Explorer will show it as `svchost.exe`. **winglass
shows the process name uncolored** (because our binary isn't signed by
Microsoft Windows), and its signer column reads "Unsigned" in red. No
matter what you rename the file, what path you put it at, or what parent
you spawn it under, the certificate cannot be forged.

The real `svchost.exe`, running from the real path, signed by
"Microsoft Windows Publisher" through the standard Windows catalog, is
green. Everything else is not.

## Keyboard

| Key | Action |
|-----|--------|
| `↑` `↓` | Move selection through the visible list |
| Click / `Enter` on a row | Open detail panel |
| `/` | Focus filter |
| `Esc` | Close detail panel, or blur the filter input |
| Skull button in detail header | Kill process (asks for confirmation) |
| Click column header | Sort by that column, click again to reverse |

## Comparison

|                                | Task Manager | Process Explorer | winglass |
|--------------------------------|:-:|:-:|:-:|
| Signature verification         | ✗ | partial (no catalog by default) | full, with catalog fallback |
| Signer identity displayed      | ✗ | signer CN | signer CN + Windows-OS flag |
| Anti-spoof (won't trust name/path) | ✗ | ✗ | ✓ |
| Full command line              | truncated | full | full |
| Loaded DLLs per process        | ✗ | ✓ | ✓, with per-DLL signature |
| Per-process network sockets    | ✗ | ✓ | ✓, with reverse DNS |
| SHA-256 of executable          | ✗ | ✗ | ✓ |
| Environment variables          | ✗ | ✓ | ✓, collapsible |
| CPU/mem history per process    | overall only | limited | 60 s sparkline per process |
| PPL / PP protection labels     | ✗ | ✗ | ✓, decoded signer type |
| Runs under an ordinary user    | ✓ | mostly | ✓, with three-tier path fallback |
| UI updated within last decade  | ✓ | ✗ | ✓ |

## Design principles

1. **Signature is truth.** The tool never trusts a process by its name or
   its path. Every color you see is derived from the signer certificate.
2. **Zero external services.** No cloud calls, no telemetry, no update
   pings. Reverse DNS uses the OS resolver. Signature verification is
   fully local.
3. **Read-only by default.** The only mutating action is Kill Process,
   and it requires explicit confirmation.
4. **Cheap enough to poll at 1 Hz.** Every command completes in under
   200 ms. Slow work goes into worker threads with their own caches.

## Non-goals

- **Auto-updater.** Adds attack surface for negligible convenience.
- **Cloud sync.** Violates the zero-external-services principle.
- **Task management for casual users.** This is for developers, security
  analysts, and admins.
- **Antivirus behavior.** winglass surfaces information; it does not act
  on threats.
- **Kernel driver.** Would open PPL inspection but demands WHQL signing
  and ongoing compliance overhead.

## Building from source

### One-shot setup for a fresh clone

Windows 10 (with App Installer) or Windows 11:

```powershell
.\scripts\setup.ps1
```

The script is idempotent. It uses `winget` to install:

- Node.js LTS
- Rustup (which brings the MSVC toolchain)
- Visual Studio 2022 Build Tools with the C++ workload

Then sets rustup's default to `stable-x86_64-pc-windows-msvc` and runs
`npm install`. Safe to re-run.

### Development

```powershell
npm run tauri dev
```

Live reload for the Svelte frontend; Rust changes trigger an incremental
cargo rebuild. First cold build compiles ~400 crates in ~2 minutes.
Subsequent builds are seconds.

### Release build

```powershell
npm run tauri build
```

Produces three artifacts under `src-tauri\target\release\`:

- `winglass.exe` — portable, PE-embedded icon, ~8 MB
- `bundle\msi\winglass_*.msi` — MSI installer
- `bundle\nsis\winglass_*.exe` — NSIS installer

### Regenerating the app icon

The 1024×1024 source PNG is drawn programmatically by
`scripts\gen-icon.ps1` (System.Drawing, Bezier-curve shield glyph on a
dark rounded background — no external image tooling required). To
regenerate every Windows size and the multi-resolution `.ico`:

```powershell
.\scripts\gen-icon.ps1
npm run tauri -- icon assets/icon-source.png
```

### Toolchain gotcha

If `link.exe` fails with `error: export ordinal too large: 113249` or
similar, your `cargo` is resolving to a mingw/GNU toolchain instead of
MSVC. The mingw linker cannot handle the export table size of the
Tauri + windows-rs graph.

Fix: uninstall any standalone "Rust stable GNU" install from Programs
and Features so the rustup shim in `%USERPROFILE%\.cargo\bin` wins.
The setup script does this on a fresh machine, but a preexisting install
has to go manually.

## Architecture summary

**Rust backend** — Tauri v2 exposes three commands (`list_processes`,
`get_process_detail`, `kill_process`) backed by a `Mutex<AppState>`.
State owns:

- A `sysinfo::System` for CPU/memory/basic-metadata
- Per-PID caches: `exe_path`, `sig`, `dns`, `dll`, `io_state`,
  `io_delta`, `io_total`, `cpu_history`, `mem_history`, `sha`
- Two background workers reachable through mpsc channels: signature
  verification (`verify::start_worker`) and reverse DNS
  (`dns::start_worker`)

**Frontend** — SvelteKit 5 in single-page mode with Tailwind CSS v4 for
styling and Lucide-svelte for icons. Two components: the process table
route (`+page.svelte`) and the detail panel (`DetailPanel.svelte`).
Both poll their Tauri command every 1 s.

**Windows APIs** — sysinfo covers the basics; everything else is direct
calls via the `windows` crate:

- `WinVerifyTrust` + the catalog admin family (`CryptCATAdmin*`) for
  signature verification
- `WTHelperProvDataFromStateData` chain for signer CN extraction
- `NtQuerySystemInformation(SystemProcessIdInformation, 88)` for PPL exe
  path resolution
- `NtQueryInformationProcess(ProcessProtectionInformation, 61)` for
  PPL/PP labels
- `EnumProcessModulesEx` for DLL enumeration
- `GetProcessIoCounters` for disk I/O deltas
- `GetExtendedTcpTable` / `GetExtendedUdpTable` for per-process sockets
- `GetNameInfoW` for reverse DNS
- `sha2` (Rust crate) for SHA-256

Deeper technical notes for contributors live in
[`PROJECT.md`](./PROJECT.md).

## License

MIT OR Apache-2.0 at your option. Contributions welcome under the same
dual-license terms.

## Acknowledgements

- Sysinternals and Process Hacker prior art — the catalog-verification
  and `SystemProcessIdInformation` techniques are their invention;
  winglass just wraps them in a modern UI.
- Tauri, SvelteKit, Tailwind, Lucide, and the `windows` crate maintainers.
