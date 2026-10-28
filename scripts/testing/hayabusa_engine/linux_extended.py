"""Additional real-server tests; only isolated local services are touched."""
import json
import os
from pathlib import Path
import re
import subprocess
import time
import yaml

NAME = 'Server.Analysis.Windows.EventLogs.HayabusaEngine'
MONITOR = 'Server.Monitor.Windows.EventLogs.HayabusaEngine'


def exercise(ctx):
    query, collect, rows_for, seed, run = (ctx[k] for k in ('query', 'collect', 'rows_for', 'seed', 'run'))
    work, binary, config = (ctx[k] for k in ('work', 'binary', 'config'))
    original = (ctx['definitions']/ctx['artifact_path'].name).read_text()
    class Evidence(dict):
        def __setitem__(self, key, value):
            super().__setitem__(key, value)
            (work/'extended-progress.json').write_text(json.dumps(self, indent=2)+'\n')
    results = Evidence()

    def install(name, text):
        path = work/(name+'.yaml')
        path.write_text(text)
        result = query(f'SELECT artifact_set(definition=read_file(filename={json.dumps(str(path))})).name AS Name FROM scope()')
        assert result[0]['Name'] == name, result

    def status(flow, name=NAME):
        return [r for r in rows_for(flow, name) if r['Kind'] == 'Status']

    for label, replacement, limits in [
        ('exit_zero_without_output', 'execve(argv=["/bin/true"],', {}),
        ('timeout', 'execve(argv=["/bin/sleep", "120"],', {'timeout': 3}),
    ]:
        name = 'Custom.Test.'+label
        text = original.replace('name: '+NAME, 'name: '+name, 1)
        text, changed = re.subn(r'execve\(argv=\[HBExe,.*?\],', lambda _: replacement, text, count=1, flags=re.S)
        assert changed == 1
        install(name, text)
        started = time.time()
        flow, base, logs, messages, uploads = collect('F.Success', artifact=name, limits=limits)
        states = status(flow, name)
        assert any(r['Level'] == 'ERROR' for r in logs), messages
        assert not any(r.get('Success') for r in states), states
        if label == 'exit_zero_without_output':
            assert len(uploads) == 1 and states[0]['ReturnCode'] == 0, states
        else:
            assert time.time()-started < 30
            # execve must not leave its sleeper running after the collector timeout.
            process = subprocess.run(['pgrep', '-af', '^/bin/sleep 120$'], capture_output=True, text=True)
            assert not process.stdout, process.stdout
        results[label] = dict(flow_id=flow, status=states, uploads=len(uploads), errors=[r['message'] for r in logs if r['Level']=='ERROR'])

    # Fault injection tests retention, not a claimed Hayabusa crash. Invalid or
    # truncated raw bytes must survive without being parsed into detections.
    for label, payload, diagnostic in [
        ('partial_nonzero_diagnostic', b'{"RuleTitle":"Injected partial"}\n', True),
        ('partial_nonzero', b'{"RuleTitle":"Injected partial"}\n', False),
        ('truncated_nonzero', b'{"RuleTitle":"unfinished\xff', False),
    ]:
        name = 'Custom.Test.' + label
        fixture_path = work/(label+'.jsonl')
        fixture_path.write_bytes(payload)
        shell = 'cp "$1" "$2"; '
        if diagnostic:
            shell += 'mkdir -p "$3/logs"; printf "Injected failure\\n" > "$3/logs/errorlog-injected.log"; '
        shell += 'exit 7'
        replacement = 'execve(argv=["/bin/bash", "-c", '+json.dumps(shell)+', "partial-test", '+json.dumps(str(fixture_path))+', Timeline, HayabusaDir],'
        text = original.replace('name: '+NAME, 'name: '+name, 1)
        text, changed = re.subn(r'execve\(argv=\[HBExe,.*?\],', lambda _: replacement, text, count=1, flags=re.S)
        assert changed == 1
        install(name, text)
        flow, base, logs, messages, uploads = collect('F.Success', artifact=name)
        rows = rows_for(flow, name)
        states = status(flow, name)
        assert len(states) == 1 and states[0]['ReturnCode'] == 7, states
        assert states[0]['Success'] is False and states[0]['EngineSuccess'] is False, states
        assert states[0]['HasDiagnostics'] is diagnostic and states[0]['UploadsComplete'] is True, states
        assert not any(row['Kind'] == 'Detection' for row in rows), rows
        assert sum(row['Kind'] == 'Timeline' for row in rows) == 1, rows
        assert sum(row['Kind'] == 'Manifest' for row in rows) == 1, rows
        timelines = [path for path in uploads if path.name == 'hayabusa_results.jsonl']
        assert len(timelines) == 1 and timelines[0].read_bytes() == payload, uploads
        assert len([row for row in rows if row['Kind']=='Diagnostic']) == int(diagnostic), rows
        if diagnostic:
            assert any(path.read_bytes() == b'Injected failure\n' for path in uploads), uploads
        assert rows[-1]['Kind'] == 'Status', rows
        results[label] = dict(flow_id=flow, status=states, raw_timeline_bytes=len(payload),
                             byte_exact=True, detection_rows=0, diagnostic_retained=diagnostic)

    # Explicit cancellation must stop an in-flight external process and clean staging.
    cancel_flow = query('SELECT collect_client(client_id="server", artifacts=["Custom.Test.timeout"], '
                        'env=dict(ClientId="C.123456", FlowId="F.Success"), timeout=300) AS Flow FROM scope()')[0]['Flow']['flow_id']
    cancel_base = work/'filestore/clients/server/collections'/cancel_flow
    deadline = time.time()+20
    while time.time() < deadline:
        text = (cancel_base/'logs.json').read_text() if (cancel_base/'logs.json').exists() else ''
        if '[/bin/sleep 120]' in text:
            break
        time.sleep(.2)
    else:
        raise RuntimeError('Cancellation fixture did not reach execve')
    # Destructors can run after cancellation closes the log writer; inspect the
    # actual staged/extracted directories captured before cancellation instead.
    directories = sorted(set(re.findall(r'/tmp/tmp[0-9]+', text)))
    assert directories, text
    query(f'SELECT cancel_flow(client_id="server", flow_id={json.dumps(cancel_flow)}) FROM scope()')
    deadline = time.time()+10
    while time.time()<deadline and any(Path(directory).exists() for directory in directories):
        time.sleep(.2)
    assert all(not Path(directory).exists() for directory in directories), directories
    assert not subprocess.run(['pgrep', '-af', '^/bin/sleep 120$'], capture_output=True, text=True).stdout
    results['explicit_cancellation'] = dict(flow_id=cancel_flow, external_process_stopped=True)

    corrupt = work/'corrupt.evtx'
    corrupt.write_bytes(b'This is not an EVTX file.\n')
    seed('F.Corrupt', [('corrupt.evtx', corrupt)])
    flow, base, logs, messages, uploads = collect('F.Corrupt')
    states = status(flow)
    assert states and states[0]['Success'] is False and states[0].get('HasDiagnostics') is True, states
    results['corrupt_input'] = dict(flow_id=flow, status=states, uploads=len(uploads), errors=[r['message'] for r in logs if r['Level']=='ERROR'], potential_false_success=any(r.get('Success') for r in states))

    seed('F.MixedCorrupt', [('security.evtx', work/'security.evtx'), ('corrupt.evtx', corrupt)])
    flow, base, logs, messages, uploads = collect('F.MixedCorrupt')
    states = status(flow)
    detections = [r for r in rows_for(flow) if r['Kind'] == 'Detection']
    assert states and states[0]['Success'] is False and states[0]['HasDiagnostics'] is True and len(detections) == 287, states
    results['mixed_corrupt_input'] = dict(flow_id=flow, status=states, detection_rows=len(detections), uploads=len(uploads))

    for label, limits in [('row_limit', {'max_rows': 4}), ('upload_limit', {'max_bytes': 100})]:
        flow, base, logs, messages, uploads = collect('F.Success', limits=limits)
        state = query(f'SELECT get_flow(client_id="server", flow_id={json.dumps(flow)}) AS Flow FROM scope()')[0]['Flow']
        results[label] = dict(flow_id=flow, state=state['state'], status=status(flow), rows=len(rows_for(flow)), uploads=len(uploads), errors=[r['message'] for r in logs if r['Level']=='ERROR'])
        assert state['state'] == 'ERROR' or any(r['Level']=='ERROR' for r in logs), results[label]

    # Install the actual SERVER_EVENT through its supported management function.
    # A real local Linux client then uploads fixtures and emits its own completion.
    uploader = 'Custom.Test.UploadEvtx'
    fixture = json.dumps(str(work/'security.evtx'))
    install(uploader, f'''name: {uploader}
type: CLIENT
sources:
  - query: |
      SELECT upload(file={fixture}, name="alpha/security.evtx") AS Alpha,
             upload(file={fixture}, name="beta/security.evtx") AS Beta FROM scope()
''')
    client_cfg = yaml.safe_load(run('-c', config, 'config', 'client'))
    client_cfg['Client']['server_urls'] = [f'https://127.0.0.1:{ctx["args"].port_base}/']
    client_cfg['Client']['writeback_linux'] = str(work/'client.writeback.yaml')
    client_cfg['Client'].setdefault('local_buffer', {})['filename_linux'] = str(work/'client.buffer.bin')
    client_cfg['Client']['max_poll'] = 1
    client_cfg['Client']['min_poll'] = 1
    client_path = work/'client.config.yaml'
    client_path.write_text(yaml.safe_dump(client_cfg))
    log = (work/'client.log').open('w')
    client = subprocess.Popen([str(binary), '-v', '-c', str(client_path), 'client'], stdout=log, stderr=subprocess.STDOUT)
    try:
        deadline = time.time()+45
        while time.time() < deadline:
            clients = query('SELECT client_id FROM clients()')
            real = [r['client_id'] for r in clients if r['client_id'] != 'C.123456']
            if real:
                break
            time.sleep(1)
        else:
            raise RuntimeError('Local Linux client enrollment failed; inspect client.log')
        client_id = real[0]
        added = query(f'SELECT add_server_monitoring(artifact="{MONITOR}", parameters=dict(ArtifactRegex="Custom.Test.UploadEvtx")) AS Added FROM scope()')
        assert added[0]['Added'] is not None, added
        time.sleep(2)
        source = query(f'SELECT collect_client(client_id={json.dumps(client_id)}, artifacts=["{uploader}"]) AS Flow FROM scope()')[0]['Flow']['flow_id']
        deadline = time.time()+90
        forwarded = []
        while time.time() < deadline:
            forwarded = query(f'SELECT * FROM source(client_id="server", artifact="{MONITOR}/Results") WHERE ClientId={json.dumps(client_id)} AND FlowId={json.dumps(source)}')
            if len([r for r in forwarded if r.get('Kind') == 'Detection']) == 10:
                break
            time.sleep(1)
        else:
            raise RuntimeError(f'Installed monitor did not finish real client flow {source}; rows={forwarded}')
        statuses = [r for r in forwarded if r['Kind']=='Status']
        assert len(statuses)==1 and statuses[0]['Success'] is True, statuses
        analysis = statuses[0]['AnalysisFlowId']
        source_uploads = query(f'SELECT * FROM uploads(client_id={json.dumps(client_id)}, flow_id={json.dumps(source)})')
        assert len(source_uploads)==2, source_uploads
        results['installed_monitor_real_linux_client'] = dict(client_id=client_id, source_flow=source, analysis_flow=analysis, upload_count=len(source_uploads), detection_rows=10, status=statuses)
        timeout_monitor = 'Custom.Test.TimeoutMonitor'
        monitor_text = (ctx['definitions']/ctx['args'].monitor.name).read_text().replace('name: '+MONITOR, 'name: '+timeout_monitor, 1).replace(NAME, 'Custom.Test.timeout')
        install(timeout_monitor, monitor_text)
        query(f'SELECT rm_server_monitoring(artifact="{MONITOR}") FROM scope()')
        query(f'SELECT add_server_monitoring(artifact="{timeout_monitor}", parameters=dict(ArtifactRegex="Custom.Test.UploadEvtx", AnalysisTimeout="3")) FROM scope()')
        time.sleep(2)
        source = query(f'SELECT collect_client(client_id={json.dumps(client_id)}, artifacts=["{uploader}"]) AS Flow FROM scope()')[0]['Flow']['flow_id']
        deadline = time.time()+30
        while time.time() < deadline:
            forwarded = query(f'SELECT * FROM source(client_id="server", artifact="{timeout_monitor}/Results") WHERE FlowId={json.dumps(source)}')
            statuses = [r for r in forwarded if r.get('Kind') == 'AnalysisStatus']
            if statuses:
                break
            time.sleep(1)
        else:
            raise RuntimeError('Installed monitor did not report analyzer timeout')
        assert statuses[0]['State'] == 'ERROR', statuses
        assert not any(r.get('Success') for r in forwarded)
        assert not subprocess.run(['pgrep', '-af', '^/bin/sleep 120$'], capture_output=True, text=True).stdout
        results['installed_monitor_timeout'] = dict(source_flow=source, status=statuses, external_process_stopped=True)
        query(f'SELECT rm_server_monitoring(artifact="{timeout_monitor}") FROM scope()')
        early_name = 'Custom.Test.EarlyError'
        early = original.replace('name: '+NAME, 'name: '+early_name, 1)
        early = early.replace('LET HBRun <=', 'LET EarlyError <= log(level="ERROR", message="Injected error before slow work")\n      LET HBRun <=')
        early, changed = re.subn(r'execve\(argv=\[HBExe,.*?\],', lambda _: 'execve(argv=["/bin/sleep", "20"],', early, count=1, flags=re.S)
        assert changed == 1
        install(early_name, early)
        early_monitor = 'Custom.Test.EarlyErrorMonitor'
        monitor_text = (ctx['definitions']/ctx['args'].monitor.name).read_text().replace('name: '+MONITOR, 'name: '+early_monitor, 1).replace(NAME, early_name)
        install(early_monitor, monitor_text)
        query(f'SELECT add_server_monitoring(artifact="{early_monitor}", parameters=dict(ArtifactRegex="Custom.Test.UploadEvtx")) FROM scope()')
        time.sleep(2)
        sources = [query(f'SELECT collect_client(client_id={json.dumps(client_id)}, artifacts=["{uploader}"]) AS Flow FROM scope()')[0]['Flow']['flow_id'] for _ in range(2)]
        deadline = time.time()+60
        while time.time()<deadline:
            forwarded = query(f'SELECT * FROM source(client_id="server", artifact="{early_monitor}/Results")')
            finished = [r for r in forwarded if r.get('Kind') == 'Status']
            if len(finished)==2:
                break
            time.sleep(1)
        analyses = [r for r in forwarded if r.get('Kind') == 'AnalysisStatus']
        results['early_error_monitor'] = dict(status_rows=len(finished), analysis_rows=len(analyses), source_flows=sources)
        assert len(finished)==2 and len(analyses)==2, forwarded
        logs_by_flow=[]
        for row in analyses:
            path=work/'filestore/clients/server/collections'/row['AnalysisFlowId']/'logs.json'
            logs_by_flow.append([json.loads(line) for line in path.read_text().splitlines()])
        assert max(r['Timestamp'] for r in logs_by_flow[0]) <= min(r['Timestamp'] for r in logs_by_flow[1]), 'Early ERROR caused overlapping analyses'
        results['early_error_monitor'] = dict(status_rows=2, analysis_rows=2, serialized=True, source_flows=sources)

    finally:
        query('SELECT rm_server_monitoring(artifact="Custom.Test.EarlyErrorMonitor") FROM scope()')
        query('SELECT rm_server_monitoring(artifact="Custom.Test.TimeoutMonitor") FROM scope()')
        query(f'SELECT rm_server_monitoring(artifact="{MONITOR}") FROM scope()')
        client.terminate()
        client.wait(timeout=15)
        log.close()
    return results
