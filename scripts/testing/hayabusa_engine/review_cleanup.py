#!/usr/bin/env python3
"""Observe row-limit cleanup for ten seconds after flow duration becomes positive.

Accepts review_compatibility arguments. Run with --extended-only. This probe
keeps the frontend alive during cleanup; it does not use collect()'s immediate
absence assertion. Existing analyzer and monitor definitions remain unchanged.
"""
import json
from pathlib import Path
import re
import time
import linux_extended
import review_compatibility


def exercise(ctx):
    query, work = ctx['query'], ctx['work']
    results = []
    for iteration in range(3):
        flow = query('SELECT collect_client(client_id="server", artifacts=["Server.Analysis.Windows.EventLogs.HayabusaEngine"], env=dict(ClientId="C.123456", FlowId="F.Success", MinimumLevel="informational"), max_rows=4) AS Flow FROM scope()')[0]['Flow']['flow_id']
        base = work/'filestore/clients/server/collections'/flow
        started = time.monotonic()
        closed_at = None
        observations = []
        while time.monotonic()-started < 30:
            details = query(f'SELECT get_flow(client_id="server", flow_id="{flow}") AS Flow FROM scope()')[0]['Flow']
            if details.get('execution_duration', 0)>0:
                if closed_at is None:
                    closed_at = time.monotonic()
                logs = [json.loads(line) for line in (base/'logs.json').read_text().splitlines()]
                messages = '\n'.join(row['message'] for row in logs if 'query: running' not in row['message'])
                directories = sorted(set(re.findall(r'/tmp/tmp[0-9]+', messages)))
                existing = [directory for directory in directories if Path(directory).exists()]
                observations.append({'seconds_after_duration_observed': round(time.monotonic()-closed_at, 4), 'existing_directories': existing})
                if directories and not existing:
                    break
                if time.monotonic()-closed_at >= 10:
                    break
            time.sleep(.025)
        result = {'iteration': iteration+1, 'flow_id': flow, 'state': details.get('state'), 'execution_duration': details.get('execution_duration'), 'total_requests': details.get('total_requests'), 'query_stats': details.get('query_stats'), 'observations': observations, 'cleanup_complete': bool(observations) and not observations[-1]['existing_directories']}
        results.append(result)
        (work/'cleanup-progress.json').write_text(json.dumps(results, indent=2)+'\n')
    assert all(result['cleanup_complete'] for result in results), results
    return {'row_limit_cleanup': results}


linux_extended.exercise = exercise
if __name__ == '__main__':
    review_compatibility.main()
