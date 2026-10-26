#!/usr/bin/env python3
"""Linux amd64 integration test against a real isolated Velociraptor frontend."""
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

NAME = 'Server.Analysis.Windows.EventLogs.HayabusaEngine'

DOWNLOADS = {
    'velociraptor': ('https://github.com/Velocidex/velociraptor/releases/download/v0.77.2/velociraptor-v0.77.2-linux-amd64', '6c4c23c466d892788ff56ddcd3a31f844e4c0d797ade454c5e2625eb9e427077'),
    'security.evtx': ('https://raw.githubusercontent.com/omerbenamram/evtx/8930398ff61c56bdc0f8ab5781e4093ee34d9026/samples/security.evtx', '5f29a03cf8c1b4bfbd82c4074ccc81ecfe85d7ee15375afc352ed5025c9a4d8d'),
    'hello.evtx': ('https://raw.githubusercontent.com/omerbenamram/evtx/7a33a8fde5489bae14c8bd832fa29b9cded8a01b/samples/Microsoft-Windows-HelloForBusiness%254Operational.evtx', 'f03dd7f04d728a118d33ee3e5f3900912a9e3cb6e26e13491ec754c47e1d29d2'),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workdir', type=Path, help='Keep all downloaded assets, keys and evidence here; otherwise use a new temporary directory')
    parser.add_argument('--artifact', type=Path, required=True, help='Analyzer YAML to test')
    parser.add_argument('--monitor', type=Path, help='Optional companion monitor YAML for completion-event integration tests')
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
    if args.monitor:
        run('artifacts', 'verify', args.monitor)
        shutil.copyfile(args.monitor, definitions / args.monitor.name)
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

    def collect(source, artifact=NAME, parameters=True, overrides=None):
        values = dict(ClientId='C.123456', FlowId=source, MinimumLevel='informational') if parameters else {}
        values.update(overrides or {})
        vql = f'SELECT collect_client(client_id="server", artifacts=[{json.dumps(artifact)}], env=dict(' + ','.join(f'{key}={json.dumps(value)}' for key, value in values.items()) + ')) AS Flow FROM scope()'
        flow = query(vql)[0]['Flow']['flow_id']
        base = work / 'filestore/clients/server/collections' / flow
        deadline = time.time() + 180
        while time.time() < deadline:
            states = query(f'SELECT * FROM flows(client_id="server") WHERE session_id={json.dumps(flow)}')
            if states and states[0]['state'] in ('FINISHED', 'ERROR'):
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
        for label, flow, files, expected_rows, overrides in [
            ('success', 'F.Success', [('security.evtx', work/'security.evtx')], 287, {}),
            ('duplicate', 'F.Duplicate', [('alpha/security.evtx', work/'security.evtx'), ('beta/security.evtx', work/'security.evtx')], 574, {}),
            ('empty_timeline', 'F.EmptyTimeline', [('hello.evtx', work/'hello.evtx')], 0, {}),
            ('default_medium', 'F.Medium', [('security.evtx', work/'security.evtx')], 5, {'MinimumLevel': 'medium'}),
            ('renamed', 'F.Renamed', [('evidence.log', work/'security.evtx')], 287, {'EvtxRegex': '(?i)\\.log$'}),
        ]:
            seed(flow, files)
            result, base, logs, messages, uploads = collect(flow, overrides=overrides)
            assert not any(row['Level']=='ERROR' for row in logs), messages
            timeline = [json.loads(line) for line in (base/'uploads/auto/hayabusa_results.jsonl').read_text().splitlines() if line.strip()]
            assert len(timeline) == expected_rows, len(timeline)
            manifest = [json.loads(line) for line in (base/'uploads/auto/input_manifest.jsonl').read_text().splitlines() if line.strip()]
            assert len({row['LocalPath'] for row in manifest}) == len(files)
            if timeline:
                assert all(isinstance(row['Details'], dict) and isinstance(row['ExtraFieldInfo'], dict) for row in timeline)
                assert len(uploads) == 2, len(uploads)
            else:
                assert len(uploads) == 2
            emitted = rows_for(result)
            statuses = [row for row in emitted if row['Kind'] == 'Status']
            assert len(statuses) == 1 and statuses[0]['Success'] is True and statuses[0]['ReturnCode'] == 0, statuses
            detections = [row for row in emitted if row['Kind'] == 'Detection']
            assert len(detections) == expected_rows, len(detections)
            assert all(row['ClientId'] == 'C.123456' and row['FlowId'] == flow for row in detections)
            assert {row['Kind'] for row in emitted} >= {'Timeline', 'Manifest'}
            report[label] = dict(flow_id=result, timeline_rows=len(timeline), detection_rows=len(detections), uploads=len(uploads))
        seed('F.Missing', [('missing.evtx', None)])
        for label, flow, parameters in [('missing_file','F.Missing',True),('missing_collection','F.DoesNotExist',True),('missing_parameters','',False)]:
            result, _, logs, messages, uploads = collect(flow, parameters=parameters)
            assert not uploads and any(row['Level']=='ERROR' for row in logs), messages
            assert 'Hayabusa:' not in messages and 'Takajo:' not in messages
            assert [row['Success'] for row in rows_for(result) if row['Kind'] == 'Status'] == [False]
            report[label] = dict(flow_id=result, uploads=0)
        for label, overrides in [('invalid_threads', {'Threads': '0'}), ('invalid_level', {'MinimumLevel': 'invalid'})]:
            result, _, logs, messages, uploads = collect('F.Success', overrides=overrides)
            assert not uploads and any(row['Level'] == 'ERROR' for row in logs), messages
            assert 'execve: Running' not in messages
            assert [row['Success'] for row in rows_for(result) if row['Kind'] == 'Status'] == [False]
            report[label] = dict(flow_id=result, uploads=0)
        original = (definitions / artifact_path.name).read_text()
        for label, command, expected_uploads in [('hayabusa_failure', 'HBExe', 1)]:
            custom = 'Custom.Test.' + label
            definition = original.replace('name: '+NAME, 'name: '+custom, 1)
            replacement = 'execve(argv=["/bin/false"],'
            definition, changed = re.subn(r'execve\(argv=\['+command+r',.*?\],', lambda _: replacement, definition, count=1, flags=re.S)
            assert changed == 1
            clone = work / (label+'.yaml')
            clone.write_text(definition)
            assert query(f'SELECT artifact_set(definition=read_file(filename={json.dumps(str(clone))})).name AS Name FROM scope()')[0]['Name'] == custom
            result, base, logs, messages, uploads = collect('F.Success', artifact=custom)
            assert len(uploads) == expected_uploads, messages
            assert any(row['Level']=='ERROR' for row in logs), messages
            failure_status = [row for row in rows_for(result, custom) if row['Kind'] == 'Status']
            assert len(failure_status) == 1 and failure_status[0]['Success'] is False and failure_status[0]['ReturnCode'] != 0, failure_status
            report[label] = dict(flow_id=result, uploads=len(uploads))
        if args.monitor:
            monitor_name = 'Server.Monitor.Windows.EventLogs.HayabusaEngine'
            report['monitor_sha256'] = hashlib.sha256((definitions / args.monitor.name).read_bytes()).hexdigest()
            before = {row['session_id'] for row in query('SELECT * FROM flows(client_id="server")')}
            for source in ('F.MonitorA', 'F.MonitorB'):
                seed(source, [('security.evtx', work/'security.evtx')])
            output = (work/'monitor.jsonl').open('w')
            errors = (work/'monitor.stderr').open('w')
            watcher = subprocess.Popen([str(binary), '-v', '-a', str(api), 'query', '--format=jsonl',
                f'SELECT * FROM Artifact.{monitor_name}() LIMIT 14'], env=env, stdout=output, stderr=errors)
            try:
                time.sleep(2)
                # Nonmatching artifact and server completions must not schedule work.
                for client, source, artifacts in [
                    ('C.123456', 'F.Ignored', ['Unrelated.Artifact']),
                    ('server', 'F.Loop', ['Windows.KapeFiles.Targets']),
                    ('C.123456', 'F.MonitorA', ['Windows.KapeFiles.Targets']),
                    ('C.123456', 'F.MonitorB', ['Windows.Triage.Targets']),
                ]:
                    sent = query('SELECT send_event(artifact="System.Flow.Completion", client_id="server", row=dict('
                          f'ClientId={json.dumps(client)}, FlowId={json.dumps(source)}, '
                          f'Flow=dict(artifacts_with_results={json.dumps(artifacts)}))) AS Sent FROM scope()')
                    assert sent[0]['Sent'] is not None, sent
                watcher.wait(timeout=90)
                assert watcher.returncode == 0, (work/'monitor.stderr').read_text()
            finally:
                if watcher.poll() is None:
                    watcher.terminate()
                    watcher.wait(timeout=10)
                output.close()
                errors.close()
            forwarded = [json.loads(line) for line in (work/'monitor.jsonl').read_text().splitlines() if line.strip()]
            detections = [row for row in forwarded if row['Kind'] == 'Detection']
            statuses = [row for row in forwarded if row['Kind'] == 'AnalysisStatus']
            assert len(detections) == 10 and len(statuses) == 2, forwarded
            assert all(row['State'] == 'FINISHED' for row in statuses), statuses
            assert all(row['ClientId'] == 'C.123456' for row in forwarded)
            assert all(row['Success'] for row in forwarded if row['Kind'] == 'Status')
            assert {row['FlowId'] for row in forwarded} == {'F.MonitorA', 'F.MonitorB'}
            created = {row['session_id'] for row in query('SELECT * FROM flows(client_id="server")')} - before
            assert created == {row['AnalysisFlowId'] for row in statuses}, created
            flow_logs = []
            for status in statuses:
                base = work/'filestore/clients/server/collections'/status['AnalysisFlowId']
                logs = [json.loads(line) for line in (base/'logs.json').read_text().splitlines()]
                assert not any(row['Level'] == 'ERROR' for row in logs), logs
                for directory in re.findall(r'remov(?:ing|ed) tempdir (\S+)', '\n'.join(row['message'] for row in logs)):
                    assert not Path(directory).exists(), directory
                flow_logs.append(logs)
            assert max(row['Timestamp'] for row in flow_logs[0]) <= min(row['Timestamp'] for row in flow_logs[1]), 'Monitor analyses overlapped'
            report['monitor'] = dict(analysis_flows=sorted(created), detection_rows=len(detections), serialized=True, ignored_nonmatching_and_server_events=True)
        large = query((Path(__file__).parent/'large_staging.vql').read_text())
        assert large[0]['Ready'] and not large[1]['Ready'], large
        assert large[0]['StageStats'][0]['Total'] == 1500
        assert large[1]['FailStats'][0]['Successful'] == 1499
        report['large_staging'] = large
        (work/'report.json').write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report, indent=2))
        print(f'Evidence and isolated config: {work}')
    finally:
        frontend.terminate()
        frontend.wait(timeout=15)
        log.close()


if __name__ == '__main__':
    main()
