# security-suite

A single [HFS](https://github.com/rejetto/hfs) plugin that combines the
functionality of six previously separate security plugins into one, licensed
AGPL-3.0. See [LICENSE](./LICENSE) for the full text and the required
attribution notice for the six projects this incorporates.

## Features

- **Connection-level IP blocking** with an auto-switching lookup: a native
  roaring-bitmap addon for O(1) IPv4 lookups when available on the current
  platform, falling back automatically to sorted-range binary search
  otherwise. IPv6 is supported via sorted BigInt ranges. The lookup mode can
  also be forced manually.
- **Dynamic rate-limit banning** — bans an IP after too many requests in a
  short window, mirrored into HFS's own built-in block list so it's visible
  and manageable from the Admin panel.
- **Header / User-Agent blocking** — disconnects requests whose headers
  match a configured regular expression.
- **CORS by path** — adds permissive CORS headers, but only for requests
  whose path matches a configured allow-list.
- **Dot-path rewriting** — strips a leading dot from path segments
  (`/.file` -> `/file`), optionally restricted to configured path prefixes.
- **Tarpit / honeypot** — slows down responses matching User-Agent, URL, or
  status-code patterns; honeypot mode can stream either an infinite filler
  byte or a **custom file, looped**, at a configurable rate.
- **Optional backend threat-intel sync** — off by default. Can periodically
  report anonymized, aggregated violation counts to a companion backend
  server, and/or fetch a shared blocklist feed from it. See the companion
  `security-suite-backend` project (private, proprietary skeleton) for the
  server side of this.

## Architecture: one middleware, one newSocket listener

The six original plugins each registered their own `middleware` hook with
HFS (six separate registrations). security-suite registers **two** hooks
total instead:

- A single `newSocket` listener does the IP-blocking check (dynamic bans +
  bulk blocklist) for every new TCP connection, **before HTTP parsing even
  starts**. This is deliberately kept separate from `middleware` rather than
  folded into it: rejecting a connection here is cheaper than anything
  possible once HFS has already started parsing the HTTP request, since
  `antidos` (one of the six originals) already used this same technique for
  its own bans.
- A single `middleware` export runs everything else (header blocking,
  dot-path rewriting, CORS, tarpit pre-checks, rate-limit accounting) in one
  pass on the way down, and returns one combined closure that handles the
  tarpit response-throttling on the way back up.

## Configuration

All settings live under one Admin-panel config screen, grouped by the
config key prefix each feature owns:

| Prefix | Feature | Replaces |
|---|---|---|
| `ip_*` | Bulk IP blocklist + lookup-mode switcher | `hfs-ip-blocklist` |
| `rateLimit_*` | Dynamic rate-limit banning | `antidos` |
| `headerBlock_*` | Header / User-Agent regex blocking | `hfs-blocker` |
| `cors_*` | CORS by path | `hfs-cors-by-path` |
| `dotRewrite_*` | Dot-path rewriting | `hfs-dot-rewrite-paths` |
| `tarpit_*` | Tarpit / honeypot | `hfs-tarpit` |
| `backend_*` / `_backend_apiKey` | Optional backend sync (new) | — |

## Migrating from the original plugins

If you currently run any of the six original plugins, uninstall them after
installing security-suite and re-enter their settings under the matching
prefix above (settings are not automatically imported, since the config
shapes were consolidated and in some cases renamed):

| Uninstall | Config now lives under |
|---|---|
| `antidos` | `rateLimit_*` |
| `hfs-blocker` | `headerBlock_*` |
| `hfs-cors-by-path` | `cors_*` |
| `hfs-dot-rewrite-paths` | `dotRewrite_*` |
| `hfs-ip-blocklist` | `ip_*` |
| `hfs-tarpit` | `tarpit_*` |

Running any of the six originals alongside security-suite is not
recommended — you'd get duplicate (and possibly conflicting) middleware
behavior for the same feature.

## Installation

Copy the contents of this repository's `dist` folder (and any matching
`dist-PLATFORM-ARCH` folder for your OS/architecture, used for the roaring
bitmap native addon) into HFS's `plugins/security-suite` folder, or install
via Admin-panel once published. See HFS's
[plugin development reference](https://github.com/rejetto/hfs/blob/main/dev-plugins.md)
for the general mechanism.

Starting the plugin is the only step required.

- If a prebuilt roaring-bitmap binary is bundled for your exact
  platform/architecture/libc/Node-ABI combination, it's used automatically
  for O(1) IPv4 lookups.
- If not, the plugin automatically uses its pure-JavaScript sorted-ranges
  binary search instead. Every feature works correctly either way; only the
  lookup speed for very large bulk blocklists differs.

### Supported platforms for the native roaring-bitmap addon

| Platform | Arch | libc | Node ABI (major) covered |
|---|---|---|---|
| Windows | x64 | - | 115, 127, 137, 141 (Node 20, 22, 23, 24) |
| macOS | arm64 | - | 115, 127, 137, 141 |
| macOS | x64 | - | 115, 127, 137 |
| Linux | x64 | glibc, musl | 115, 127, 137, 141 |
| Linux | arm64 | glibc | 115, 127, 137, 141 |
| Linux | arm (armhf) | glibc | 115, 127, 137 (Node 24 dropped 32-bit ARM entirely, so there is no 141 build for this one) |

The x64/darwin/win32 binaries come from upstream's
[roaring-node](https://github.com/SalvatorePreviti/roaring-node) GitHub
Releases, which never publishes Linux ARM builds. The Linux arm64/armhf
binaries are instead cross-built by this repo's own
[`build-arm-roaring.yml`](.github/workflows/build-arm-roaring.yml) GitHub
Actions workflow, compiling the same upstream source under QEMU emulation —
this happens once in CI, not on any machine running HFS; nothing is ever
compiled on the target host. Any platform/arch/libc/ABI combination not
listed above automatically uses the pure-JS sorted-ranges fallback instead.

## Uninstalling

Removing the plugin's folder removes everything HFS considers part of the
plugin, including its per-plugin config section and its `storage` folder
(where the downloaded/built blocklist data lives) — this is standard HFS
plugin behavior, not something security-suite does specially.

One thing is **not** covered by that: any IP the rate-limiter dynamically
banned is also mirrored into HFS's own built-in `block` list (the core
`block:` config HFS ships with, so bans are visible/manageable from the
Admin panel while the plugin is running) — mirrored entries are tagged with
a `security-suite` comment. Because that list is a core HFS feature, not
plugin-owned data, HFS does not remove those entries just because the
plugin that created them was uninstalled. security-suite removes its own
tagged entries from that list on unload, so a normal disable/uninstall
leaves nothing behind; the only residue possible is if the HFS process is
killed (not stopped normally) between a ban being mirrored and the plugin's
next clean unload.

## Credits

security-suite incorporates modified portions of:

- [rejetto/antidos](https://github.com/rejetto/antidos)
- [rejetto/hfs-blocker](https://github.com/rejetto/hfs-blocker)
- [feuerswut/hfs-cors-by-path](https://github.com/feuerswut/hfs-cors-by-path)
- [feuerswut/hfs-dot-rewrite-paths](https://github.com/feuerswut/hfs-dot-rewrite-paths)
- [feuerswut/hfs-ip-blocklist](https://github.com/feuerswut/hfs-ip-blocklist)
- [feuerswut/hfs-tarpit](https://github.com/feuerswut/hfs-tarpit)

See [LICENSE](./LICENSE) for the full attribution notice and license texts.
