# Engine comparison evidence and follow-up

The new artifact provides an explicit Hayabusa executable option. This work does
**not** establish a speed ratio, detection-parity result, or new default engine.
The integration harness tests orchestration and results from a public fixture;
it is not a controlled comparison of the two detection engines.

## Reproducible package audit (2026-10-26 UTC)

The [curated Hayabusa package](https://sigma.velocidex.com/artifacts/Velociraptor-Hayabusa-Rules.zip)
was downloaded from the link on the
[official artifact page](https://sigma.velocidex.com/docs/artifacts/windows.hayabusa.rules/).
The embedded artifact reports build time `2026-10-19T15:27:27Z`.

- ZIP SHA256: `a9c2909cf701b64545fbead387faf7af55860b42d0ae1512f707fda81be79814`
- Converted rule files: 4,936 (4,933 `.yml` files and three generated
  `.yml-1` correlation companion files).
- `rejected.json`: 96 diagnostics across 67 distinct source paths.
- Diagnostics include unsupported modifiers (`expand`, `fieldref`, `i`), missing
  log-source mappings, and legacy timeframe detections.

These are conversion diagnostics, not a count of missed detections. Several
rejected paths are explicitly deprecated or unsupported. In particular, three
rejected legacy timeframe rules have packaged correlation replacements:
`PW Spray 2` and `User Guessing 2` use `value_count`; `PW Guessing 2` uses
`event_count`. The package therefore does include correlation rules.

A specific omission is **Possible Token Impersonation**, rule ID
`46614e82-7926-41f9-85aa-006b98c5c2a3`. Its source path is rejected with
`Invalid modifier fieldref`; that ID is absent from all converted rule files.
The [upstream rule](https://github.com/Yamato-Security/hayabusa-rules/blob/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4624_Med_Logon-Type9-NewInteractive_PossibleTokenImpersonation.yml)
is stable, medium severity and compares `SubjectUserName|fieldref` with
`TargetUserName`. The same ID and comparison are present in the pinned
[Hayabusa 4.2.0 Linux musl package](https://github.com/Yamato-Security/hayabusa/releases/download/v4.2.0/hayabusa-4.2.0-lin-x64-musl.zip),
SHA256 `8060dac9c6b61da5566a638bfc11b0db4c0c51b0600113901fd2a84b3360b4c6`.
This verifies a packaging difference; it does not prove this rule fires on the
public fixture, that every upstream rule works, or that one engine always wins.

Reproduce the static audit with Python's standard library:

```sh
python3 scripts/testing/hayabusa_engine/audit_conversion.py --download
# Or use a retained copy:
python3 scripts/testing/hayabusa_engine/audit_conversion.py --zip /path/to/curated.zip
```

The URL is mutable. The script requires the observed digest and stops if the
package changes, so a later download cannot silently support these dated claims.
Keep the original ZIP with any published benchmark results.

## Native correlation support

Do not describe Velociraptor's native engine as having no correlation support.
The [implementation at the tested binary's commit](https://github.com/Velocidex/velociraptor/blob/c0c9dd609/vql/sigma/evaluator/correlation.go)
implements `event_count`, `value_count` and `temporal`; its switch rejects other
correlation types, including `temporal_ordered`. The integration harness binary
is Velociraptor 0.77.2, commit `c0c9dd609`, built 2026-08-10. The development
checkout is newer, so runtime conclusions must identify the binary actually used.

The [curated project's explanation](https://sigma.velocidex.com/docs/sigma_in_velociraptor/)
also explains that log-source and field mappings are necessary and that curation
can reject rules with unsupported sources or fields. Rule-package conversion,
engine capabilities and enabled rule filters are separate sources of differences.

## Fair follow-up procedure

1. Retain engine binaries and SHA256 values, the complete Hayabusa rule/config
   directory, the curated ZIP, its embedded original/converted rules, and
   `rejected.json`. Record exact commands and host CPU/RAM details.
2. Begin with the harness's pinned
   [Security EVTX fixture](https://raw.githubusercontent.com/omerbenamram/evtx/8930398ff61c56bdc0f8ab5781e4093ee34d9026/samples/security.evtx)
   (SHA256 `5f29a03cf8c1b4bfbd82c4074ccc81ecfe85d7ee15375afc352ed5025c9a4d8d`).
   Stage it as `Security.evtx` for the native package's fixed channel filename.
   This small fixture is useful for diagnostics, not representative IR performance.
3. Compare rule IDs and full rule content before comparing hits. A shared rule
   ID alone does not prove equivalent revisions. Keep a shared, equivalent rule
   subset for engine-semantic testing and report package-only rules separately.
4. Explicitly align severity, status, title exclusions, noisy/deprecated/unsupported
   rules, date bounds, record recovery, duplicate suppression and input files.
   Native `RuleExclusions` uses title regexes; Hayabusa's exclusions/configuration
   are not automatically equivalent. Existing native server defaults are high and
   critical, stable; Hayabusa's broad defaults must not be compared as though equal.
5. Normalize results by rule ID and event identity (computer, channel, record ID,
   timestamp). Analyze correlation groups separately. Investigate differing hits
   against original event fields and rule semantics; total row counts alone do
   not establish detection quality.
6. Only then measure repeated runs with fixed concurrency, warm/cold-cache policy,
   wall time and peak memory. Separate download/staging/upload overhead from
   engine execution. For coverage, add known-positive and known-negative fixtures,
   including field comparison and each supported correlation type.

No aligned native-versus-Hayabusa benchmark was run for this change. The package
audit above is sufficient evidence to avoid promising rule parity while retaining
both workflows and making their engine choice explicit.
