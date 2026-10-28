#!/usr/bin/env python3
"""Controlled fault: a process writes partial JSONL + diagnostics, then exits 7.

This tests artifact retention logic, not a demonstrated Hayabusa crash. Only an
isolated Custom.Review clone is changed; the supplied analyzer stays unchanged.
Use a fresh --workdir (contains temporary server credentials; never commit it).
Example:
  python3 review_partial_output.py --artifact /path/to/analyzer.yaml \
      --asset-cache /path/to/hash-verified/downloads --port-base 31590
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

from test import NAME, DOWNLOADS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workdir', type=Path, help='Keep all downloaded assets, keys and evidence here; otherwise use a new temporary directory')
    parser.add_argument('--artifact', type=Path, required=True, help='Analyzer YAML to test')
    parser.add_argument('--asset-cache', type=Path, help='Reuse hash-verified downloads, never server state')
    parser.add_argument('--port-base', type=int, default=28990, help='Four free consecutive loopback ports')
    args = parser.parse_args()
    artifact_path = args.artifact.resolve()
    work = (args.workdir or Path(tempfile.mkdtemp(prefix='hayabusa-engine-integration-'))).resolve()
    work.mkdir(parents=True, exist_ok=True)
    if (work / 'server.config.yaml').exists():
        raise RuntimeError('Use a fresh workdir; refusing to reuse server state')
    for filename, (url, expected) in DOWNLOADS.items():
        target = work / filename
        if not target.exists():
            cached = args.asset_cache / filename if args.asset_cache else None
            if cached and cached.is_file():
                shutil.copyfile(cached, target)
            else:
                urllib.request.urlretrieve(url, target)
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        if expected and digest != expected:
            raise RuntimeError(f'Unexpected SHA256 for {filename}: {digest}')
    binary = work / 'velociraptor'
    binary.chmod(0o755)
    env = dict(os.environ)
    config, api = work / 'server.config.yaml', work / 'api.config.yaml'

    def run(*argv):
        try:
            result = subprocess.run([str(binary), *map(str, argv)], env=env, text=True, capture_output=True, check=True)
        except subprocess.CalledProcessError as error:
            print(error.stderr, file=sys.stderr)
            raise
        return result.stdout

    run('artifacts', 'verify', artifact_path)
    config.write_text(run('config', 'generate', '--merge', json.dumps({
        'Datastore': {'location': str(work / 'datastore'), 'filestore_directory': str(work / 'filestore')},
        'Frontend': {'bind_address': '127.0.0.1', 'bind_port': args.port_base + 0},
        'GUI': {'bind_address': '127.0.0.1', 'bind_port': args.port_base + 1},
        'API': {'bind_address': '127.0.0.1', 'bind_port': args.port_base + 2},
        'Monitoring': {'bind_address': '127.0.0.1', 'bind_port': args.port_base + 3},
    })))
    run('-c', config, 'config', 'api_client', '--name=testadmin', api)
    run('-c', config, 'user', 'add', '--role=administrator', 'testadmin', 'local-integration-only')
    definitions = work / 'definitions'
    definitions.mkdir()
    shutil.copyfile(artifact_path, definitions / artifact_path.name)
    log = (work / 'frontend.log').open('w')
    frontend = subprocess.Popen([str(binary), '-c', str(config), '-D', str(definitions), 'frontend', '--disable-panic-guard'], env=env, stdout=log, stderr=subprocess.STDOUT)

    def query(vql):
        return [json.loads(line) for line in run('-a', api, 'query', '--format=jsonl', vql).splitlines() if line.strip()]

    def seed(flow, files):
        base = work / 'filestore/clients/C.123456/collections' / flow
        rows = []
        for relative, source in files:
            dest = base / 'uploads/file' / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            if source:
                shutil.copyfile(source, dest)
            size = dest.stat().st_size if source else 99
            rows.append(dict(vfs_path=relative, Type='', _Components=['clients', 'C.123456', 'collections', flow, 'uploads', 'file', *relative.split('/')], file_size=size, uploaded_size=size, _accessor='file'))
        base.mkdir(parents=True, exist_ok=True)
        (base / 'uploads.json').write_text(''.join(json.dumps(row)+'\n' for row in rows))

    def rows_for(flow, artifact=NAME):
        return query(f'SELECT * FROM source(client_id="server", flow_id={json.dumps(flow)}, artifact={json.dumps(artifact + "/Results")})')

    def collect(source, artifact=NAME, parameters=True, overrides=None, limits=None):
        values = dict(ClientId='C.123456', FlowId=source, MinimumLevel='informational') if parameters else {}
        values.update(overrides or {})
        vql = f'SELECT collect_client(client_id="server", artifacts=[{json.dumps(artifact)}], env=dict(' + ','.join(f'{key}={json.dumps(value)}' for key, value in values.items()) + ')' + ''.join(f', {key}={json.dumps(value)}' for key, value in (limits or {}).items()) + ') AS Flow FROM scope()'
        flow = query(vql)[0]['Flow']['flow_id']
        base = work / 'filestore/clients/server/collections' / flow
        deadline = time.time() + 180
        while time.time() < deadline:
            states = query(f'SELECT get_flow(client_id="server", flow_id={json.dumps(flow)}) AS Flow FROM scope()')
            if states and states[0]['Flow']['state'] in ('FINISHED', 'ERROR') and states[0]['Flow'].get('execution_duration', 0) > 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError(f'Flow timeout: {flow}')
        logs = [json.loads(line) for line in (base / 'logs.json').read_text().splitlines() if line.strip()]
        messages = '\n'.join(row['message'] for row in logs)
        for directory in re.findall(r'removing tempdir (\S+)', messages):
            assert not Path(directory).exists(), directory
        for directory in re.findall(r'removed tempdir (\S+)', messages):
            assert not Path(directory).exists(), directory
        files = [file for file in (base / 'uploads').rglob('*') if file.is_file()]
        return flow, base, logs, messages, files

    report = {'artifact_sha256': hashlib.sha256((definitions / artifact_path.name).read_bytes()).hexdigest(), 'velociraptor_version': run('version').strip()}
    try:
        for _ in range(50):
            try:
                query('SELECT * FROM info()')
                break
            except subprocess.CalledProcessError:
                if frontend.poll() is not None:
                    raise RuntimeError((work / 'frontend.log').read_text())
                time.sleep(0.2)
        else:
            raise RuntimeError('Frontend API did not start')
        seed('F.Success', [('security.evtx', work/'security.evtx')])
        original=artifact_path.read_text()
        custom='Custom.Review.PartialNonzero'
        shell="printf '%s\\n' '{\"Timestamp\":\"2026-10-28T00:00:00Z\",\"RuleTitle\":\"Injected partial output\"}' > \"$1\"; mkdir -p \"$2/logs\"; printf '%s\\n' 'Injected engine failure after partial timeline' > \"$2/logs/errorlog-review.log\"; test -s \"$1\" || exit 8; wc -c \"$1\"; exit 7"
        call='FROM execve(argv=["/bin/bash", "-c", '+json.dumps(shell)+', "partial-test", Timeline, HayabusaDir], sep="\\n", length=65536)'
        modified,n=re.subn(r'FROM execve\(argv=\[HBExe,.*?length=65536\)',lambda m:call,original,flags=re.S)
        assert n==1
        modified=modified.replace('name: '+NAME,'name: '+custom,1)
        (work/'partial-clone.yaml').write_text(modified)
        query('SELECT artifact_set(definition='+json.dumps(modified)+') FROM scope()')
        result, directory, logs, messages, files=collect('F.Success',artifact=custom)
        bytes_match = re.search(r'Hayabusa: (\d+) .*hayabusa_results[.]jsonl', messages)
        assert bytes_match and int(bytes_match[1]) == 75, messages
        rows=rows_for(result,custom)
        statuses=[r for r in rows if r['Kind']=='Status']
        assert len(statuses)==1 and statuses[0]['Success'] is False and statuses[0]['ReturnCode']==7
        assert statuses[0]['HasDiagnostics'] is True
        assert {r['Kind'] for r in rows}=={'Manifest','Diagnostic','Status'},rows
        localpaths=[]
        for row in rows:
            if row['Kind']=='Manifest':
                manifest=[f for f in files if f.name=='input_manifest.jsonl'][0]
                for line in manifest.read_text().splitlines(): localpaths.append(json.loads(line)['LocalPath'])
        for f in localpaths:
            assert not Path(f).parent.parent.exists()
        report.update(
            scenario="Controlled execve substitute; not a demonstrated Hayabusa crash",
            injected_exit_code=7,
            partial_timeline_bytes=int(bytes_match[1]),
            observed_kinds=[r['Kind'] for r in rows],
            status={k:v for k,v in statuses[0].items() if k not in ('ClientId','FlowId')},
            uploaded_files=[str(f.relative_to(directory)) for f in files],
            all_temporary_workdirs_removed=True,
            partial_timeline_uploaded=any(r['Kind']=='Timeline' for r in rows),
            reproduced=True)
        (work/'report.json').write_text(json.dumps(report,indent=2))
        print(json.dumps(report,indent=2))
    finally:
        frontend.terminate()
        frontend.wait(timeout=15)
        log.close()


if __name__ == '__main__':
    main()
