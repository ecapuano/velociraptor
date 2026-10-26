# Hayabusa engine integration validation

On Linux amd64 with Python 3:

```sh
python3 scripts/testing/hayabusa_engine/test.py \
  --artifact /path/to/velociraptor-docs/content/exchange/artifacts/Server.Analysis.Windows.EventLogs.HayabusaEngine.yaml \
  --monitor /path/to/velociraptor-docs/content/exchange/artifacts/Server.Monitor.Windows.EventLogs.HayabusaEngine.yaml
```

The harness downloads SHA256-verified Velociraptor 0.77.2 and public EVTX fixtures.
The artifact downloads its pinned Hayabusa release through the actual tool inventory.
No Takajo, endpoint, production server, or repository secrets are required. Four
loopback ports starting at 28990 must be free (`--port-base` changes them).

Each run creates a fresh, isolated frontend and datastore, an administrator API
identity, and genuine SERVER collections. Source upload metadata and EVTX files
are seeded manually because no Windows endpoint is available. Files are consumed
through `uploads()` and the `fs` accessor; output uploads are real server uploads.
This tests post-collection processing, not client collection or transport.

Use `--asset-cache /path/to/downloads` to reuse the three hash-verified download
files. Never reuse a server configuration or datastore. `--workdir /new/path`
chooses the evidence directory; an existing server configuration is rejected.
The frontend terminates in a finally block. Evidence is retained for inspection.
The directory includes test private keys: do not publish or commit it. Only the
summary `report.json` is suitable for sharing.

The security fixture is pinned to omerbenamram/evtx commit
8930398ff61c56bdc0f8ab5781e4093ee34d9026. With Hayabusa 4.2.0, bundled rules,
verbose JSONL, informational minimum level, and two threads, an independent CLI
run produces 287 rows. Duplicate inputs produce 574 rows. These counts validate
this specific fixture/configuration; they do not establish detection coverage
or comparative performance.

The HelloForBusiness fixture exercises successful execution with no detections.
Hayabusa 4.2.0's channel filter skips its events and emits a newline-only timeline.
This does not establish coverage of that channel.

The harness checks timeline/manifest uploads, detection row context, duplicate
filename preservation, absent inputs, tool failure, and temporary-directory
cleanup. `large_staging.vql` verifies the aggregate guard across a 1,500-row VQL
materialization spill; it does not run 1,500 EVTX analyses.

With `--monitor`, the harness invokes the actual monitor through the server API,
publishes two synthetic client completion events to the real completion journal,
and verifies that it schedules two genuine server collections serially and
forwards ten medium-or-higher detections plus status rows. Nonmatching artifact
and server-completion events must not schedule analyses. This validates monitor
logic and journal delivery, not GUI installation, durable queuing, restart
recovery, long-running hunts, or the timeout-cancellation path.

Both artifact snapshots are copied into the isolated definitions directory;
`report.json` records their SHA256 hashes and the Velociraptor version. Tests also
check medium-level output (five detections), renamed EVTX selection, invalid
parameters, and successful/failed status rows with external process return codes.
