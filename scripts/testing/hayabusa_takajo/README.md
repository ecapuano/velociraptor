Run on Linux amd64 with Python 3 and `dpkg-deb`:

```sh
python3 scripts/testing/hayabusa_takajo/test.py
```

GitHub Actions runs the same harness on an Ubuntu 24.04 amd64 runner in
`.github/workflows/hayabusa-takajo.yml`. It runs on pushes and pull requests
that change this artifact, its tests, or the workflow, and can also be dispatched
manually once the workflow is on the repository's default branch. No repository
secrets or Windows endpoint are needed. The job uses a downloaded, pinned
Velociraptor release rather than building the repository's Go sources.

Each run uploads `report.json` and the harness console log as the
`hayabusa-takajo-results` artifact, retained for seven days, including the console
log when a test fails. Generated server/API configuration and private keys stay
in the runner's temporary directory and are excluded from uploaded artifacts.

The harness downloads hash checked Velociraptor 0.77.2 and public EVTX fixtures,
extracts Ubuntu's hash checked libpcre3 package into its temporary directory,
starts an isolated frontend on localhost ports 18990–18993, and uses an API
administrator to schedule genuine SERVER collections. Hayabusa 2.14.0 and
Takajo 2.5.0 download through the artifact's pinned, hash checked tool inventory.
The libpcre3 library is needed by Takajo; no system package is installed.

Source client collection upload metadata and EVTX files are seeded manually in
the isolated filestore because no Windows endpoint is available. The artifact
reads those files through `uploads()` and the `fs` accessor. Analysis output
files are genuine server flow uploads, not a simulated upload function. Source
client identity is C.123456. No Hayabusa or Takajo runs on a client.

`--workdir /absolute/path` preserves downloaded tools, the isolated configuration
(including test private keys), flow metadata, logs, output files and report.json.
Use a new directory for each run. Do not commit its contents. The frontend is
terminated in a finally block. The temporary evidence directory is retained.

Tests exercise:

- Full Hayabusa → Takajo analysis: 285 verbose timeline rows, 18 Takajo files,
  timeline and input manifest (20 uploads).
- Two uploads sharing a basename: distinct staging names, 570 timeline rows,
  both source files preserved in the manifest.
- Empty timeline: the zero-byte timeline and manifest are uploaded and Takajo
  is skipped. The HelloForBusiness fixture has six events according to
  Velociraptor, but pinned Hayabusa 2.14 cannot deserialize these events and
  returns success with no detections. This test proves empty-output handling;
  it does not establish Hayabusa coverage for that channel.
- Missing parameters, missing source collection and missing uploaded content:
  error logs, no tool execution and no output uploads.
- Custom artifact clones substitute `/bin/false` for each analyzer separately:
  failed Hayabusa preserves only the manifest; failed Takajo preserves the
  successful timeline and manifest and emits no partial Takajo outputs.
- A custom Takajo clone emits nested fixture output: recursive uploads preserve
  case-0/scriptblock-logs/nested/test.ps1 and its contents.
- A VQL staging guard regression test materializes 1,500 rows: successful rows
  remain ready after spilling; one failed copy makes the guard false. This
  validates the guard, not 1,500 actual EVTX analyses.
- Every collection's logged temporary directories are absent after completion.

The public security.evtx fixture comes from omerbenamram/evtx at commit
8930398ff61c56bdc0f8ab5781e4093ee34d9026. SHA256 is
5f29a03cf8c1b4bfbd82c4074ccc81ecfe85d7ee15375afc352ed5025c9a4d8d.
Velociraptor parses 2,261 events; Hayabusa emits 285 detection timeline rows.
The harness pins all downloaded assets by URL and SHA256. The fixtures are
EVTX event records.

Local verification on 2026-09-29 used Velociraptor 0.77.2 (commit c0c9dd609),
Hayabusa 2.14.0 and Takajo 2.5.0 on Ubuntu 24.04 amd64. Actual success flow
F.DAU1UB58LC1JG produced 20 uploads; final duplicate flow F.DAU1V2VNIFVAM
produced 570 timeline rows; empty flow F.DAU1V31TI6AP8 uploaded two files.
The standalone harness independently reruns all cases and records flow IDs.
