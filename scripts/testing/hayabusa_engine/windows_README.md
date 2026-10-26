# Reviewable Windows → Linux validation

This GitHub Actions workflow is prepared locally. It runs on pushes only to the
dedicated `hayabusa-windows-validation` branch, or by manual dispatch if already
registered. It does not require a default-branch change. Preparing these
files does not run a Windows test. Publication and execution require the user's
explicit approval; do not push or dispatch it as part of local validation.

The workflow needs an immutable commit containing the reviewed Exchange analyzer,
monitor and existing Windows endpoint artifact. Set `windows_artifacts.json` to
the reviewed repository and full 40-character commit SHA before publication.
Optional dispatch inputs can override that source. Placeholder values fail closed. The harness checkout uses the dispatched workflow revision.
The job runs exclusively on an ephemeral GitHub-hosted `windows-2022` runner;
the bootstrap refuses other environments. It does not use a lab or production
host, install a persistent service, or require repository secrets.

## What an executed PASS establishes

1. Import a hash-verified official Ubuntu 22.04 root filesystem as a temporary
   WSL1 distribution. Start a real Linux Velociraptor 0.77.2 frontend bound to
   loopback, with new temporary keys, datastore and filestore.
2. Verify the Windows Velociraptor 0.77.2 executable's SHA256 and Authenticode
   signature. Start a real native Windows client and verify Windows enrollment.
3. Run the existing, unmodified `Windows.EventLogs.Hayabusa` artifact directly on
   Windows, first on a fixture-only directory (`UpdateRules=N`, JSONL, medium;
   expected five rows), then with its default live Windows directory and default
   `UpdateRules=Y` (JSONL, no predetermined row count). Check process execution
   logs, timeline upload/parseability, Results agreement, absence of collection
   errors, removal of temporary executable directories, and no remaining Hayabusa
   process via a separate native Windows audit artifact. A native `dfir-timeline --help` banner
   preflight uses the hash-pinned live-response package. The test never disables
   Defender; the sanitized report includes a count of related Defender detections
   when available. The existing artifact does not expose the updater exit code;
   this check proves the default update command ran, not that its network update
   completed successfully.
4. Install the actual `Server.Monitor.Windows.EventLogs.HayabusaEngine` using
   `add_server_monitoring` before scheduling collections. Do not seed filestore
   rows or inject completion events.
5. Collect two differently named copies of the public Security EVTX fixture
   through the Windows client. Require ten medium-or-higher detections from the
   installed monitor's resulting analysis, distinct manifest entries and cleanup.
6. Run `wevtutil epl` on the Windows client to export its live System, Application
   and Security channels. Upload all three exports, verify they contain parseable
   events, and require successful monitor-triggered analysis. Live detection count
   is intentionally unspecified; the hosted image determines its event content.
7. Upload the public fixtures alongside a deliberately corrupt EVTX. Require
   retained fixture detections, uploaded diagnostics and final `Success=false`.
   This checks the analyzer's distinction between process exit and clean analysis.
8. Stop the client/frontend, unregister only the uniquely named test distribution,
   and remove the temporary directory. Upload only `windows-report.json` containing
   checks, counts, hashes and status. Never upload private keys, writeback files,
   server/client configurations, raw logs, event contents or the filestore.

The scripts are `windows_bootstrap.ps1` (host setup/cleanup) and `windows_wsl.py`
(Linux frontend and assertions). Python reuses pinned Linux binary metadata from
`test.py`; it does not call that harness's seeded-flow tests. Rootfs Python,
PyYAML, libpcre3 and CA certificates are already installed; no pip/apt/bootstrap
script from a third-party action is needed.

## Pinned dependencies and primary sources

- [Official Windows 2022 runner image](https://github.com/actions/runner-images/blob/main/images/windows/Windows2022-Readme.md)
  documents WSLv1 enabled. The runner image itself changes; successful reports
  record `ImageVersion`.
- [Microsoft's distro import instructions](https://learn.microsoft.com/en-us/windows/wsl/use-custom-distro)
  document `wsl --import` and its `--version` option.
- [Canonical rootfs](https://cloud-images.ubuntu.com/wsl/releases/22.04/current/ubuntu-jammy-wsl-amd64-wsl.rootfs.tar.gz),
  checked against [Canonical SHA256SUMS](https://cloud-images.ubuntu.com/wsl/releases/22.04/current/SHA256SUMS),
  inspected 2026-10-26:
  `de9f6149da07b90350a3ccd94b4858b82fef71f0ec2982acb93de583c4c87585`.
  The URL is mutable; hash mismatch fails closed rather than using a new image.
  The [manifest](https://cloud-images.ubuntu.com/wsl/releases/22.04/current/ubuntu-jammy-wsl-amd64-wsl.manifest)
  includes Python 3.10, PyYAML and libpcre3.
- [Windows Velociraptor 0.77.2 release](https://github.com/Velocidex/velociraptor/releases/tag/v0.77.2):
  `686e4f5888fdd66d07ace3b6c1cbd7d2dd0d8d5fb4d3b5d905a7df3341dfb86f`.
  The digest was obtained from the official release asset metadata. Runtime also
  requires Windows Authenticode status `Valid`.
- Linux Velociraptor and the public EVTX source/hash are pinned in `test.py`.
  Hayabusa 4.2.0 and its archive digest are pinned in the reviewed analyzer YAML.
- Checkout and report-upload actions use full commit IDs already used by this
  repository's workflows. The job grants `contents: read` only.

## Limits

This is genuine Windows execution and genuine upload transport to Linux binaries,
with an installed server event monitor. WSL1 uses Windows syscall translation and
shared localhost networking; it is not an independent Linux kernel, a remote
network, a Windows service deployment, or a representative performance benchmark. The
endpoint artifact runs natively on Windows; only the server uses WSL1.
A PASS does not validate WSL2, all Windows versions, remote TLS/firewall setups,
production throughput, AV behavior or detection parity between engines.

The Windows/WSL run has not been executed during preparation. Local checks can
validate Python syntax, workflow syntax and the generated upload artifact's VQL;
they cannot prove Windows signing, WSL import, Windows event permissions, or the
cross-platform runtime path. Report those separately after an approved execution.
