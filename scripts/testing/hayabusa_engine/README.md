# Hayabusa engine integration validation

On Linux amd64 with Python 3:

```sh
python3 scripts/testing/hayabusa_engine/test.py \
  --artifact /path/to/velociraptor-docs/content/exchange/artifacts/Server.Analysis.Windows.EventLogs.HayabusaEngine.yaml \
  --monitor /path/to/velociraptor-docs/content/exchange/artifacts/Server.Monitor.Windows.EventLogs.HayabusaEngine.yaml
```

The harness downloads SHA256-verified Velociraptor 0.77.2 and public EVTX fixtures.
The artifact downloads its pinned Hayabusa release through the actual tool inventory.
The baseline suite needs no endpoint, Takajo, production server, or repository
secrets. Four
loopback ports starting at 28990 must be free (`--port-base` changes them).

Each run creates a fresh, isolated frontend and datastore, an administrator API
identity, and genuine SERVER collections. The baseline suite seeds source upload
metadata and EVTX files manually. Files are consumed through `uploads()` and the
`fs` accessor; output uploads are real server uploads. These baseline cases test
post-collection processing. The extended Linux suite below tests actual client
transport; the [Windows suite](windows_README.md) tests a real Windows client and
live event-log collection.

Use `--asset-cache /path/to/downloads` to reuse the three hash-verified download
files. Never reuse a server configuration or datastore. `--workdir /new/path`
chooses the evidence directory; an existing server configuration is rejected.
The frontend terminates in a finally block. Evidence is retained for inspection.
The directory includes test private keys: do not publish or commit it. Only the
summary `report.json` is suitable for sharing.

The security fixture is pinned to omerbenamram/evtx commit
8930398ff61c56bdc0f8ab5781e4093ee34d9026. With Hayabusa 4.3.0, bundled rules,
verbose JSONL, informational minimum level, and two threads, an independent CLI
run produces 287 rows. Duplicate inputs produce 574 rows. These counts validate
this specific fixture/configuration; they do not establish detection coverage
or comparative performance. The 4.3.0 fixture baseline has the same
(RuleID, RecordID, Level) counts as the independently recorded 4.2.0 baseline.

The HelloForBusiness fixture exercises successful execution with no detections.
Hayabusa 4.3.0's channel filter skips its events and emits a newline-only timeline.
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
logic and journal delivery. Installed monitoring and timeout/cancellation are
covered by the extended suite below. GUI installation, durable queuing, restart
recovery, and long-running hunts are not established by these tests.

Both artifact snapshots are copied into the isolated definitions directory;
`report.json` records their SHA256 hashes and the Velociraptor version. Tests also
check medium-level output (five detections), renamed EVTX selection, invalid
parameters, and successful/failed status rows with external process return codes.

## Extended Linux lifecycle tests

Add `--extended` to run the baseline suite followed by `linux_extended.py`.
This requires PyYAML. `--extended-only` skips baseline cases during iteration.
The extended cases use a real Linux client process with its own writeback and
TLS connection to the isolated frontend. They install the monitor with
`add_server_monitoring()`, upload duplicate EVTX fixtures through the client,
and inspect persisted Server Events results from genuine flow completion.
This exercises client transport and installed monitoring; it is not a Windows
endpoint or live Windows event-log collection test.

Other extended cases cover exit-zero with missing output, collector timeout,
explicit cancellation and external-process cleanup, corrupt and mixed EVTX,
row/upload limits, and installed-monitor timeout reporting. Executable failure
and sleep cases substitute test commands in isolated artifact clones; normal
and corrupt-input cases invoke real Hayabusa. `extended-progress.json` retains
completed case evidence even if a later test fails.

The tests exposed two issues fixed in the proposed analyzer: Hayabusa can exit
zero after rejecting corrupt EVTX, so generated diagnostics must be preserved
and make final Success false; and Velociraptor 0.77.2 does not apply its collection
deadline while draining unnamed materialized LET statements. Wrapping work in
a named query makes its watchdog active while external execution runs. Final
Status is emitted after detections so truncation cannot leave an early success
marker suggesting complete results.

A third regression test logs an error before a 20-second external operation and
queues two real client collections. Velociraptor can expose state ERROR while
execution_duration is still zero. The previous monitor started the second
analysis early and forwarded neither final status. The monitor now requires
positive execution_duration before reading results or starting the next scan.
`early-error-regression.json` records the prior monitor's approximately
8.3-second overlap; the final extended run requires both final statuses and
nonoverlapping collection logs.
