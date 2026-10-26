#!/usr/bin/env python3
"""Ephemeral Linux frontend orchestrator for the Windows/WSL1 hosted-runner test."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import traceback
import urllib.request

import yaml
from test import DOWNLOADS

ANALYZER = 'Server.Analysis.Windows.EventLogs.HayabusaEngine'
MONITOR = 'Server.Monitor.Windows.EventLogs.HayabusaEngine'
ENDPOINT = 'Windows.EventLogs.Hayabusa'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shared', type=Path, required=True)
    parser.add_argument('--windows-shared', required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    args = parser.parse_args()
    shared = args.shared.resolve()
    work = Path('/root/hayabusa-windows-integration')
    work.mkdir(mode=0o700)  # Refuse stale server state.
    report = {'platform': 'Windows Server 2022 client -> Ubuntu 22.04 WSL1 server',
              'status': 'RUNNING', 'checks': {}}
    frontend = None
    stage = 'bootstrap'
    config, api = work/'server.config.yaml', work/'api.config.yaml'
    binary = work/'velociraptor'
    url, expected = DOWNLOADS['velociraptor']
    urllib.request.urlretrieve(url, binary)
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == expected
    binary.chmod(0o755)

    def run(*argv):
        result = subprocess.run([str(binary), *map(str, argv)], capture_output=True,
                                text=True, timeout=120)
        if result.returncode:
            # Private CLI output can contain configuration. Do not print it.
            (work/'last-command.stderr').write_text(result.stderr)
            categories = ['ResourceExhausted', 'message larger than max', 'DeadlineExceeded',
                'deadline exceeded', 'PermissionDenied', 'Unavailable', 'connection refused',
                'No such file', 'not found', 'undefined', 'Syntax', 'EOF', 'Canceled',
                'timeout', 'failed to parse', 'invalid character', 'Too many rows']
            report['failed_cli'] = {'exit_code': result.returncode,
                'stderr_bytes': len(result.stderr.encode()),
                'stderr_categories': [word for word in categories if word.lower() in result.stderr.lower()],
                'was_api_query': 'query' in argv}
            raise RuntimeError('Velociraptor command failed; private diagnostic retained in WSL')
        return result.stdout

    def query(vql):
        return [json.loads(line) for line in run('-a', api, 'query', '--format=jsonl', vql).splitlines()
                if line.strip()]

    def install(name, query_text):
        definition = yaml.safe_dump({'name': name, 'type': 'CLIENT',
            'precondition': "SELECT * FROM info() WHERE OS = 'windows'",
            'sources': [{'name': 'Uploads', 'query': query_text}]})
        path = work/(name+'.yaml')
        path.write_text(definition)
        assert query(f'SELECT artifact_set(definition=read_file(filename={json.dumps(str(path))})).name AS Name FROM scope()')[0]['Name'] == name

    def poll(fn, seconds=240):
        deadline = time.monotonic()+seconds
        while time.monotonic() < deadline:
            if (shared/'stop').exists():
                raise RuntimeError('Windows bootstrap requested stop')
            value = fn()
            if value:
                return value
            time.sleep(1)
        raise TimeoutError('Timed out waiting for test stage')

    try:
        os.umask(0o077)
        definitions = work/'definitions'
        definitions.mkdir()
        for name in (ANALYZER, MONITOR, ENDPOINT):
            source = args.artifacts/(name+'.yaml')
            shutil.copyfile(source, definitions/source.name)
            report[name+'_sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
        run('artifacts', 'verify', *sorted(definitions.glob('*.yaml')))
        config.write_text(run('config', 'generate', '--merge', json.dumps({
            'Datastore': {'location': str(work/'datastore'), 'filestore_directory': str(work/'filestore')},
            'Frontend': {'bind_address': '127.0.0.1', 'bind_port': 28990},
            'GUI': {'bind_address': '127.0.0.1', 'bind_port': 28991},
            'API': {'bind_address': '127.0.0.1', 'bind_port': 28992},
            'Monitoring': {'bind_address': '127.0.0.1', 'bind_port': 28993},
        })))
        run('-c', config, 'config', 'api_client', '--name=testadmin', api)
        run('-c', config, 'user', 'add', '--role=administrator', 'testadmin', 'ephemeral-test-only')
        with (work/'frontend.log').open('w') as log:
            frontend = subprocess.Popen([str(binary), '-c', str(config), '-D', str(definitions),
                'frontend', '--disable-panic-guard'], stdout=log, stderr=subprocess.STDOUT)
        def api_ready():
            try:
                return query('SELECT * FROM info()')
            except RuntimeError:
                return False
        poll(api_ready, 60)
        client_config = yaml.safe_load(run('-c', config, 'config', 'client'))
        client_config['Client'].update(server_urls=['https://127.0.0.1:28990/'],
            writeback_windows=args.windows_shared+'\\client.writeback.yaml', min_poll=1, max_poll=1)
        client_config['Client'].setdefault('local_buffer', {})['filename_windows'] = args.windows_shared+'\\client-buffer.bin'
        # Client config contains public CA/server material; private writeback remains ephemeral.
        (shared/'client.config.yaml').write_text(yaml.safe_dump(client_config))
        (shared/'ready').write_text('ready\n')
        stage = 'Windows client enrollment'
        def windows_client():
            return [r for r in query('SELECT client_id, os_info FROM clients()')
                    if r.get('os_info', {}).get('system', '').lower() == 'windows']
        enrolled = poll(windows_client, 120)
        assert len(enrolled) == 1, 'Expected exactly one Windows client'
        client_id = enrolled[0]['client_id']
        report['client_os'] = enrolled[0]['os_info'].get('system')
        root = args.windows_shared
        fixture_paths = [{'Path': root+'\\security.evtx', 'Name': 'alpha/security.evtx'},
                         {'Path': root+'\\security.evtx', 'Name': 'beta/security.evtx'}]
        for suffix, paths in [('Fixture', fixture_paths), ('Mixed', fixture_paths+[
                {'Path': root+'\\corrupt.evtx', 'Name': 'corrupt.evtx'}])]:
            rows = ','.join('dict(Path='+json.dumps(p['Path'])+', Name='+json.dumps(p['Name'])+')' for p in paths)
            install('Custom.Test.WindowsHayabusa'+suffix,
                    'SELECT Name, upload(file=Path, name=Name) AS Upload FROM foreach(row=['+rows+'])')
        install('Custom.Test.WindowsHayabusaLive', '''
LET Temp <= tempdir()
LET Export(Channel) = SELECT * FROM execve(argv=["C:/Windows/System32/wevtutil.exe", "epl", Channel,
    path_join(components=[Temp, Channel + ".evtx"]), "/ow:true"])
SELECT * FROM foreach(row=["System", "Application", "Security"], query={
  SELECT _value AS Channel,
      upload(file=path_join(components=[Temp, _value + ".evtx"]), name=_value + ".evtx") AS Upload
  FROM Export(Channel=_value)
  WHERE Complete AND if(condition=ReturnCode = 0, then=TRUE,
      else=log(level="ERROR", message="Event log export failed") AND FALSE)
})
''')
        def client_collection(name, values=None, timeout=300):
            params = ','.join(key+'='+json.dumps(value) for key, value in (values or {}).items())
            result = query(f'SELECT collect_client(client_id={json.dumps(client_id)}, artifacts=[{json.dumps(name)}], env=dict({params}), timeout={timeout}, max_rows=1000000, max_bytes=1073741824) AS Flow FROM scope()')
            flow = result[0]['Flow']['flow_id']
            def finished():
                state = query(f'SELECT get_flow(client_id={json.dumps(client_id)}, flow_id={json.dumps(flow)}) AS Flow FROM scope()')[0]['Flow']
                return state if state.get('state') in ('FINISHED', 'ERROR') else False
            state = poll(finished, timeout+60)
            assert state['state'] == 'FINISHED', 'Native Windows artifact collection failed'
            return flow

        for label, options in [
            ('endpoint_fixture', {'EvtxDirectory': root+'\\endpoint-fixture',
                'UpdateRules': 'N', 'OutputFormat': 'jsonl', 'MinimalLevel': 'medium'}),
            # Omit UpdateRules and EvtxDirectory: exercise the artifact's real defaults.
            ('endpoint_live_default_update', {'OutputFormat': 'jsonl'}),
        ]:
            stage = label
            flow = client_collection(ENDPOINT, options, timeout=600)
            logs = query(f'SELECT * FROM flow_logs(client_id={json.dumps(client_id)}, flow_id={json.dumps(flow)})')
            assert not any(r.get('Level') == 'ERROR' for r in logs), 'Endpoint artifact logged execution errors'
            messages = '\n'.join(r.get('message', '') for r in logs)
            assert 'hayabusa-4.2.0-win-x64.exe' in messages and 'execve' in messages, 'Missing native process execution evidence'
            if label == 'endpoint_live_default_update':
                assert 'update-rules' in messages, 'Default rule update did not execute'
            files = query(f'SELECT * FROM uploads(client_id={json.dumps(client_id)}, flow_id={json.dumps(flow)})')
            files = [r for r in files if r.get('Type') != 'idx']
            assert len(files) == 1 and files[0]['file_size'] > 0, 'Missing endpoint timeline upload'
            # Aggregate on the server: live event rows can exceed gRPC's message limit.
            # Compare nonempty JSONL line count too, so silently skipped bad JSON fails.
            parsed = query(f'SELECT count() AS N FROM foreach(row={{ SELECT * FROM uploads(client_id={json.dumps(client_id)}, flow_id={json.dumps(flow)}) WHERE NOT Type = "idx" }}, query={{ SELECT * FROM parse_jsonl(filename=vfs_path, accessor="fs") }}) GROUP BY 1')
            raw_lines = query(f'SELECT count() AS N FROM foreach(row={{ SELECT * FROM uploads(client_id={json.dumps(client_id)}, flow_id={json.dumps(flow)}) WHERE NOT Type = "idx" }}, query={{ SELECT * FROM parse_lines(filename=vfs_path, accessor="fs") WHERE Line != "" }}) GROUP BY 1')
            emitted = query(f'SELECT count() AS N FROM source(client_id={json.dumps(client_id)}, flow_id={json.dumps(flow)}, artifact="{ENDPOINT}/Results") GROUP BY 1')
            parsed_count = parsed[0]['N'] if parsed else 0
            assert parsed_count == (emitted[0]['N'] if emitted else 0) == (raw_lines[0]['N'] if raw_lines else 0), 'Uploaded timeline and endpoint Results differ or contain invalid JSON'
            if label == 'endpoint_fixture':
                assert parsed_count == 5, 'Pinned live-response fixture count changed; investigate rule/package differences'
            # Verify cleanup on the native Windows client, not by interpreting its paths in WSL.
            import re
            removed = sorted(set(re.findall(r'remov(?:ing|ed) tempdir (\S+)', messages)))
            assert removed, 'No endpoint temporary-directory cleanup evidence'
            paths = ','.join(json.dumps(path) for path in removed)
            audit_name = 'Custom.Test.WindowsHayabusaCleanup'
            install(audit_name, 'SELECT * FROM chain(paths={ SELECT "Path" AS Kind, _value AS Path, stat(filename=_value) AS Stat FROM foreach(row=['+paths+']) }, '
                    'processes={ SELECT "Process" AS Kind, Name FROM pslist() WHERE Name =~ "(?i)hayabusa" })')
            audit_flow = client_collection(audit_name)
            audited = query(f'SELECT * FROM source(client_id={json.dumps(client_id)}, flow_id={json.dumps(audit_flow)}, artifact="{audit_name}/Uploads")')
            assert len(audited) == len(removed) and all(r['Kind'] == 'Path' and not r.get('Stat') for r in audited), 'Endpoint executable or process survived cleanup'
            report['checks'][label] = {'uploaded_timelines': len(files), 'timeline_rows': parsed_count,
                'native_process_execution_logged': True, 'temporary_directories_removed': len(removed),
                'remaining_hayabusa_processes': 0, 'rule_update_default_exercised': label.endswith('update')}

        stage = 'install real server monitor'
        added = query(f'SELECT add_server_monitoring(artifact="{MONITOR}", parameters=dict(ArtifactRegex="^Custom.Test.WindowsHayabusa", AnalysisTimeout="300")) AS Added FROM scope()')
        assert added[0]['Added'] is not None
        time.sleep(3)
        for suffix, expected_count in [('Fixture', 2), ('Live', 3), ('Mixed', 3)]:
            stage = suffix+' Windows collection and monitor analysis'
            name = 'Custom.Test.WindowsHayabusa'+suffix
            flow = query(f'SELECT collect_client(client_id={json.dumps(client_id)}, artifacts=["{name}"], timeout=120) AS Flow FROM scope()')[0]['Flow']['flow_id']
            def completed():
                rows = query(f'SELECT Kind, Success, AnalysisFlowId, HasDiagnostics FROM source(client_id="server", artifact="{MONITOR}/Results") WHERE ClientId={json.dumps(client_id)} AND FlowId={json.dumps(flow)}')
                return rows if any(r.get('Kind') == 'Status' for r in rows) else False
            forwarded = poll(completed, 420)
            statuses = [r for r in forwarded if r.get('Kind') == 'Status']
            assert len(statuses) == 1
            status = statuses[0]
            assert status['Success'] is (suffix != 'Mixed'), 'Unexpected analyzer success state'
            analysis = status['AnalysisFlowId']
            source_state = query(f'SELECT get_flow(client_id={json.dumps(client_id)}, flow_id={json.dumps(flow)}) AS Flow FROM scope()')[0]['Flow']
            assert source_state['state'] == 'FINISHED', 'Windows upload collection failed'
            uploads = query(f'SELECT * FROM uploads(client_id={json.dumps(client_id)}, flow_id={json.dumps(flow)})')
            uploads = [r for r in uploads if r.get('Type') != 'idx']
            assert len(uploads) == expected_count and all(r['file_size'] > 0 for r in uploads)
            emitted = query(f'SELECT Kind FROM source(client_id="server", flow_id={json.dumps(analysis)}, artifact="{ANALYZER}/Results")')
            kinds = {r.get('Kind') for r in emitted}
            assert {'Timeline', 'Manifest', 'Status'} <= kinds
            detections = [r for r in emitted if r.get('Kind') == 'Detection']
            if suffix != 'Live':
                assert len(detections) == 10, 'Public fixture detection count changed'
            if suffix == 'Mixed':
                assert status['HasDiagnostics'] is True and 'Diagnostic' in kinds
            output_uploads = query(f'SELECT * FROM uploads(client_id="server", flow_id={json.dumps(analysis)})')
            manifest_files = [r for r in output_uploads if str(r.get('client_path', '')).endswith('input_manifest.jsonl')]
            assert len(manifest_files) == 1
            manifest = query(f'SELECT * FROM foreach(row={{ SELECT * FROM uploads(client_id="server", flow_id={json.dumps(analysis)}) WHERE client_path =~ "input_manifest.jsonl$" }}, query={{ SELECT * FROM parse_jsonl(filename=vfs_path, accessor="fs") }})')
            assert len(manifest) == expected_count
            assert len({r['LocalPath'] for r in manifest}) == expected_count
            # LocalPath is the staged Linux input path; terminal status must leave none behind.
            assert all(not Path(r['LocalPath']).exists() for r in manifest)
            if suffix == 'Live':
                counts = query(f'SELECT * FROM foreach(row={{ SELECT * FROM uploads(client_id={json.dumps(client_id)}, flow_id={json.dumps(flow)}) WHERE NOT Type = "idx" }}, query={{ SELECT count() AS N FROM parse_evtx(filename=vfs_path, accessor="fs") GROUP BY 1 }})')
                assert len(counts) == 3 and all(r['N'] > 0 for r in counts), 'Live Windows exports had no parseable events'
            report['checks'][suffix] = {'windows_uploaded_files': len(uploads),
                'detections': len(detections), 'analysis_output_kinds': sorted(kinds),
                'success': status['Success'], 'input_staging_cleaned': True,
                'installed_monitor_forwarded_final_status': True}
        stage = 'complete'
        report['status'] = 'PASS'
    except Exception as error:
        report['status'] = 'FAIL'
        report['failed_stage'] = stage
        report['error_type'] = type(error).__name__
        report['error_source_lines'] = [frame.lineno for frame in traceback.extract_tb(error.__traceback__)
                                        if Path(frame.filename).name == 'windows_wsl.py']
        if isinstance(error, AssertionError):
            # All assertion messages in this harness are controlled, static strings.
            report['assertion'] = str(error)
        # Avoid serializing exceptions, queries, event contents or generated config.
        raise RuntimeError('Windows integration failed at '+stage) from None
    finally:
        if frontend is not None:
            try:
                query(f'SELECT rm_server_monitoring(artifact="{MONITOR}") FROM scope()')
            except Exception:
                pass
            frontend.terminate()
            try:
                frontend.wait(timeout=15)
            except subprocess.TimeoutExpired:
                frontend.kill()
                frontend.wait(timeout=10)
        (shared/'windows-report.json').write_text(json.dumps(report, indent=2)+'\n')
        (shared/'done').write_text('done\n')


if __name__ == '__main__':
    main()
