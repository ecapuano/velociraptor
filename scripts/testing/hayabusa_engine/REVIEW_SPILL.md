# Review of materialized-query counting

Reproduced 2026-10-28 on official Linux amd64 Velociraptor 0.77.2
(`c0c9dd609`) and 0.77.3 (`7d287b0b9`). This checks the staging-readiness
workaround discussed in [PR 1338](https://github.com/Velocidex/velociraptor-docs/pull/1338#discussion_r4402788002).
Full version strings, binary hashes, exact queries and results are in
`review-spill-results.json`. Reproduce with:

```sh
python3 scripts/testing/hayabusa_engine/review_spill.py /path/to/velociraptor
```

Both releases produced identical results:

| Rows | Materialization limit | Failed staging rows | len() | Aggregate total | Aggregate successful | Ready |
| ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| 0 | 1000 | 0 | 0 | no group | no group | false |
| 1000 | 1000 | 0 | 1000 | 1000 | 1000 | true |
| 1001 | 1000 | 0 | 0 | 1001 | 1001 | true |
| 1500 | 1000 | 0 | 0 | 1500 | 1500 | true |
| 1500 | 2000 | 0 | 1500 | 1500 | 1500 | true |
| 1500 | 1000 | 1 | 0 | 1500 | 1499 | false |

The spill occurs when row count exceeds the configured limit. Raising the
limit to 2000 restores `len()` for the same 1500 rows, isolating the failure
to disk-backed materialization rather than row generation or aggregation.
The fixture uses synthetic LocalPath values: this is a counting reproduction,
not a file-copy integration test.

Source inspection at both tested commits explains the result:

- [`LenFunction.Call`](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/vql/functions/lists.go#L164)
  calls `Materialize()` on a `types.Materializer`, supports lengths of
  slices/maps/arrays/strings/dictionaries, and otherwise returns 0.
- [`TempFileMatrializer.Materialize`](https://github.com/Velocidex/velociraptor/blob/7d287b0b988b35657e1b401f7b2ffebaf60dbcae/vql/materializer/materialize.go#L73)
  returns Null. Its `Eval` iterator instead reads the stored rows from disk.
  The materializer already tracks a private `size` field; fixing `len()` need
  not imply expanding all rows back into memory.
- The corresponding [0.77.2 len implementation](https://github.com/Velocidex/velociraptor/blob/c0c9dd609140139efcb37c47e2afa79ed57e6c84/vql/functions/lists.go#L164)
  and [disk materializer](https://github.com/Velocidex/velociraptor/blob/c0c9dd609140139efcb37c47e2afa79ed57e6c84/vql/materializer/materialize.go#L73)
  have the same relevant behavior.

Conclusion: Mike's suspicion is supported; `len()` returning 0 for a nonempty
spilled query is an upstream runtime limitation/bug, not a desirable counting
contract. Keep the artifact's aggregate count/success-count workaround for
these supported releases. It correctly handles both spill and a failed staged
row, and returns false for empty input. Suggested comment wording: “On tested
Velociraptor 0.77.2/0.77.3, len() returns 0 after a materialized query spills to
disk; count staged rows by iteration.” This avoids claiming every future
release will behave the same. No artifact code was changed by this review.
