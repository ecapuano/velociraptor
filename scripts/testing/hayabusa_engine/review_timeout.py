#!/usr/bin/env python3
"""Minimal server collection deadline reproduction, without Hayabusa or fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time

BINARY_HASHES = {
    '6c4c23c466d892788ff56ddcd3a31f844e4c0d797ade454c5e2625eb9e427077': '0.77.2',
    'c216b7be6f104da551c302d707a7e5a7126e97db33d3f1fc9d2c3b76cfa00093': '0.77.3',
}
DEFINITIONS = {
    'Materialized': 'LET Wait <= SELECT sleep(time=8) AS Slept FROM scope()\nSELECT * FROM Wait',
    'Wrapped': "SELECT * FROM query(inherit=TRUE, query='''\nLET Wait <= SELECT sleep(time=8) AS Slept FROM scope()\nSELECT * FROM Wait\n''')",
    'Lazy': 'LET Wait = SELECT sleep(time=8) AS Slept FROM scope()\nSELECT * FROM Wait',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--workdir', type=Path)
    parser.add_argument('--port-base', type=int, default=32990)
    args = parser.parse_args()
    binary = args.binary.resolve()
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    assert binary_hash in BINARY_HASHES, 'Use a pinned 0.77.2 or 0.77.3 binary'
    work = (args.workdir or Path(tempfile.mkdtemp(prefix='review-let-timeout-'))).resolve()
    work.mkdir(parents=True, exist_ok=True)
    assert not (work/'server.config.yaml').exists(), 'Use a fresh workdir'

    def run(*argv):
        result = subprocess.run([str(binary), *map(str, argv)], text=True, capture_output=True, timeout=20)
        if result.returncode:
            raise RuntimeError(result.stderr)
        return result.stdout

    definitions = work/'definitions'
    definitions.mkdir()
    for suffix, vql in DEFINITIONS.items():
        path = definitions/(suffix+'.yaml')
        path.write_text(f'name: Custom.Review.Timeout.{suffix}\ntype: SERVER\nsources:\n  - name: Results\n    query: |\n' + ''.join('      '+line+'\n' for line in vql.splitlines()))
        run('artifacts', 'verify', path)
    config, api = work/'server.config.yaml', work/'api.config.yaml'
    config.write_text(run('config', 'generate', '--merge', json.dumps({
        'Datastore': {'location': str(work/'datastore'), 'filestore_directory': str(work/'filestore')},
        'Frontend': {'bind_address': '127.0.0.1', 'bind_port': args.port_base},
        'GUI': {'bind_address': '127.0.0.1', 'bind_port': args.port_base+1},
        'API': {'bind_address': '127.0.0.1', 'bind_port': args.port_base+2},
        'Monitoring': {'bind_address': '127.0.0.1', 'bind_port': args.port_base+3},
    })))
    run('-c', config, 'config', 'api_client', '--name=reviewer', api)
    run('-c', config, 'user', 'add', '--role=administrator', 'reviewer', 'isolated-review-only')
    log = (work/'frontend.log').open('w')
    frontend = subprocess.Popen([str(binary), '-c', str(config), '-D', str(definitions), 'frontend', '--disable-panic-guard'], stdout=log, stderr=subprocess.STDOUT)
    outstanding = []

    def query(vql):
        return [json.loads(line) for line in run('-a', api, 'query', '--format=jsonl', vql).splitlines() if line.strip()]

    report = {'version': run('version').strip(), 'binary_sha256': binary_hash, 'requested_timeout_seconds': 3, 'sleep_seconds': 8, 'definitions': DEFINITIONS, 'cases': []}
    try:
        for _ in range(60):
            try:
                query('SELECT * FROM info()')
                break
            except RuntimeError:
                if frontend.poll() is not None:
                    raise RuntimeError('Isolated frontend exited')
                time.sleep(.2)
        else:
            raise RuntimeError('Isolated frontend not ready')
        for variant in ('Materialized', 'Wrapped', 'Lazy', 'Materialized', 'Wrapped'):
            name = 'Custom.Review.Timeout.'+variant
            schedule = f'SELECT collect_client(client_id="server", artifacts=["{name}"], timeout=3) AS Flow FROM scope()'
            started = time.monotonic()
            flow = query(schedule)[0]['Flow']['flow_id']
            outstanding.append(flow)
            sampled_after_deadline = None
            while time.monotonic()-started < 15:
                details = query(f'SELECT get_flow(client_id="server", flow_id={json.dumps(flow)}) AS Flow FROM scope()')[0]['Flow']
                elapsed = time.monotonic()-started
                if elapsed > 4 and sampled_after_deadline is None:
                    sampled_after_deadline = {'elapsed_seconds': round(elapsed, 3), 'state': details['state'], 'execution_duration': details.get('execution_duration', 0)}
                if details.get('execution_duration', 0) > 0:
                    break
                time.sleep(.2)
            else:
                raise RuntimeError(f'Bounded reproduction exceeded 15 seconds: {flow}')
            outstanding.remove(flow)
            rows = query(f'SELECT * FROM source(client_id="server", flow_id="{flow}", artifact="{name}/Results")')
            logs_path = work/'filestore/clients/server/collections'/flow/'logs.json'
            logs = [json.loads(line) for line in logs_path.read_text().splitlines()]
            result = {'variant': variant, 'flow_id': flow, 'schedule_vql': schedule, 'wall_seconds': round(elapsed, 3), 'execution_duration_seconds': details['execution_duration']/1e6, 'stored_request_timeout': details['request']['timeout'], 'state': details['state'], 'rows': rows, 'errors': [row['message'].strip() for row in logs if row['Level']=='ERROR'], 'after_deadline_sample': sampled_after_deadline}
            report['cases'].append(result)
            (work/'report.json').write_text(json.dumps(report, indent=2)+'\n')
        assert all(case['stored_request_timeout']==3 for case in report['cases'])
        assert all(case['execution_duration_seconds'] >= 7.5 for case in report['cases'] if case['variant']=='Materialized'), report
        assert all(2.5 <= case['execution_duration_seconds'] < 5 for case in report['cases'] if case['variant']!='Materialized'), report
        print(json.dumps(report, indent=2))
        print(f'Evidence (includes private isolated configs; share report.json only): {work}')
    finally:
        for flow in outstanding:
            try:
                query(f'SELECT cancel_flow(client_id="server", flow_id={json.dumps(flow)}) FROM scope()')
            except RuntimeError:
                pass
        frontend.terminate()
        frontend.wait(timeout=15)
        log.close()


if __name__ == '__main__':
    main()
