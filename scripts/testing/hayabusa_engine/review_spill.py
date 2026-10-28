#!/usr/bin/env python3
"""Reproduce materialized-query len/count behavior; pass Velociraptor binaries."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

reports = []
for executable in sys.argv[1:]:
    binary = Path(executable).resolve()
    report = {
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "version": subprocess.check_output([str(binary), "version"], text=True),
        "cases": [],
    }
    for rows, limit, failed_row in [(0, 1000, -1), (1000, 1000, -1),
                                     (1001, 1000, -1), (1500, 1000, -1),
                                     (1500, 2000, -1), (1500, 1000, 1200)]:
        query = f'''LET VQL_MATERIALIZE_ROW_LIMIT <= {limit}
LET Staged <= SELECT if(condition=_value != {failed_row}, then="good.evtx") AS LocalPath FROM range(end={rows})
LET Stats <= SELECT count() AS Total, sum(item=if(condition=LocalPath, then=1, else=0)) AS Successful FROM Staged GROUP BY 1
SELECT len(list=Staged) AS Len, Stats,
  Stats.Total[0] > 0 AND Stats.Total[0] = Stats.Successful[0] AS Ready FROM scope()
'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".vql") as source:
            source.write(query)
            source.flush()
            result = subprocess.run([str(binary), "query", "--format", "jsonl", "-f", source.name],
                                    capture_output=True, text=True, check=True)
        report["cases"].append({"rows": rows, "materialize_limit": limit,
                                 "failed_row": failed_row, "query": query,
                                 "result": [json.loads(line) for line in result.stdout.splitlines() if line.strip()]})
    reports.append(report)
print(json.dumps(reports, indent=2))
