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

NAME = 'Exchange.Windows.EventLogs.Hayabusa.Takajo'
ROOT = Path(__file__).resolve().parents[3]
ARTIFACT = ROOT / 'artifacts/definitions/Exchange/Windows/EventLogs/Hayabusa/Takajo.yaml'
DOWNLOADS = {
    'velociraptor': ('https://github.com/Velocidex/velociraptor/releases/download/v0.77.2/velociraptor-v0.77.2-linux-amd64', '6c4c23c466d892788ff56ddcd3a31f844e4c0d797ade454c5e2625eb9e427077'),
    'security.evtx': ('https://raw.githubusercontent.com/omerbenamram/evtx/8930398ff61c56bdc0f8ab5781e4093ee34d9026/samples/security.evtx', '5f29a03cf8c1b4bfbd82c4074ccc81ecfe85d7ee15375afc352ed5025c9a4d8d'),
    'hello.evtx': ('https://raw.githubusercontent.com/omerbenamram/evtx/7a33a8fde5489bae14c8bd832fa29b9cded8a01b/samples/Microsoft-Windows-HelloForBusiness%254Operational.evtx', 'f03dd7f04d728a118d33ee3e5f3900912a9e3cb6e26e13491ec754c47e1d29d2'),
    'libpcre3.deb': ('https://archive.ubuntu.com/ubuntu/pool/main/p/pcre3/libpcre3_8.39-13ubuntu0.22.04.1_amd64.deb', '0d1eb051047eb0c637c893f618f45e1d419863bfa3bc821897ee05ad418ba22e'),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workdir', type=Path, help='Keep all downloaded assets, keys and evidence here; otherwise use a new temporary directory')
    args = parser.parse_args()
    work = (args.workdir or Path(tempfile.mkdtemp(prefix='hayabusa-takajo-integration-'))).resolve()
    work.mkdir(parents=True, exist_ok=True)
    for filename, (url, expected) in DOWNLOADS.items():
        target = work / filename
        if not target.exists():
            urllib.request.urlretrieve(url, target)
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        if expected and digest != expected:
            raise RuntimeError(f'Unexpected SHA256 for {filename}: {digest}')
    binary = work / 'velociraptor'
    binary.chmod(0o755)
    subprocess.run(['dpkg-deb', '-x', str(work / 'libpcre3.deb'), str(work / 'libpcre3')], check=True)
    env = dict(os.environ, LD_LIBRARY_PATH=str(work / 'libpcre3/lib/x86_64-linux-gnu'))
    config, api = work / 'server.config.yaml', work / 'api.config.yaml'

    def run(*argv):
        try:
            result = subprocess.run([str(binary), *map(str, argv)], env=env, text=True, capture_output=True, check=True)
        except subprocess.CalledProcessError as error:
            print(error.stderr, file=sys.stderr)
            raise
        return result.stdout

    run('artifacts', 'verify', ARTIFACT)
    config.write_text(run('config', 'generate', '--merge', json.dumps({
        'Datastore': {'location': str(work / 'datastore'), 'filestore_directory': str(work / 'filestore')},
        'Frontend': {'bind_address': '127.0.0.1', 'bind_port': 18990},
        'GUI': {'bind_address': '127.0.0.1', 'bind_port': 18991},
        'API': {'bind_address': '127.0.0.1', 'bind_port': 18992},
        'Monitoring': {'bind_address': '127.0.0.1', 'bind_port': 18993},
    })))
    run('-c', config, 'config', 'api_client', '--name=testadmin', api)
    run('-c', config, 'user', 'add', '--role=administrator', 'testadmin', 'local-integration-only')
    log = (work / 'frontend.log').open('w')
    frontend = subprocess.Popen([str(binary), '-c', str(config), '-D', str(ARTIFACT.parents[3]), 'frontend', '--disable-panic-guard'], env=env, stdout=log, stderr=subprocess.STDOUT)

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

    def collect(source, artifact=NAME, parameters=True):
        values = dict(ClientId='C.123456', FlowId=source) if parameters else {}
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
        logs = [json.loads(line) for line in (base / 'logs.json').read_text().splitlines()]
        messages = '\n'.join(row['message'] for row in logs)
        for directory in re.findall(r'removing tempdir (\S+)', messages):
            assert not Path(directory).exists(), directory
        for directory in re.findall(r'removed tempdir (\S+)', messages):
            assert not Path(directory).exists(), directory
        files = [file for file in (base / 'uploads').rglob('*') if file.is_file()]
        return flow, base, logs, messages, files

    report = {}
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
        for label, flow, files, expected_rows in [
            ('success', 'F.Success', [('security.evtx', work/'security.evtx')], 285),
            ('duplicate', 'F.Duplicate', [('alpha/security.evtx', work/'security.evtx'), ('beta/security.evtx', work/'security.evtx')], 570),
            ('empty_timeline', 'F.EmptyTimeline', [('hello.evtx', work/'hello.evtx')], 0),
        ]:
            seed(flow, files)
            result, base, logs, messages, uploads = collect(flow)
            assert not any(row['Level']=='ERROR' for row in logs), messages
            timeline = [json.loads(line) for line in (base/'uploads/auto/hayabusa_results.jsonl').read_text().splitlines()]
            assert len(timeline) == expected_rows, len(timeline)
            manifest = [json.loads(line) for line in (base/'uploads/auto/input_manifest.jsonl').read_text().splitlines()]
            assert len({row['LocalPath'] for row in manifest}) == len(files)
            if timeline:
                assert all(isinstance(row['Details'], dict) and isinstance(row['ExtraFieldInfo'], dict) for row in timeline)
                assert len(uploads) == 20, len(uploads)
            else:
                assert len(uploads) == 2 and 'skipping Takajo' in messages
            report[label] = dict(flow_id=result, timeline_rows=len(timeline), uploads=len(uploads))
        seed('F.Missing', [('missing.evtx', None)])
        for label, flow, parameters in [('missing_file','F.Missing',True),('missing_collection','F.DoesNotExist',True),('missing_parameters','',False)]:
            result, _, logs, messages, uploads = collect(flow, parameters=parameters)
            assert not uploads and any(row['Level']=='ERROR' for row in logs), messages
            assert 'Hayabusa:' not in messages and 'Takajo:' not in messages
            report[label] = dict(flow_id=result, uploads=0)
        original = ARTIFACT.read_text()
        for label, command, expected_uploads in [('hayabusa_failure', 'HBExe', 1), ('takajo_failure', 'TKExe', 2), ('nested_output', 'TKExe', 4)]:
            custom = 'Custom.Test.' + label
            definition = original.replace('name: '+NAME, 'name: '+custom, 1)
            replacement = 'execve(argv=["/bin/false"],'
            if label == 'nested_output':
                replacement = '''execve(argv=["/bin/sh", "-c", 'mkdir -p "$1/scriptblock-logs/nested"; echo nested > "$1/scriptblock-logs/nested/test.ps1"; echo root > "$1/root.txt"', "fixture", TakajoOutput],'''
            definition, changed = re.subn(r'execve\(argv=\['+command+r',.*?\],', lambda _: replacement, definition, count=1, flags=re.S)
            assert changed == 1
            clone = work / (label+'.yaml')
            clone.write_text(definition)
            assert query(f'SELECT artifact_set(definition=read_file(filename={json.dumps(str(clone))})).name AS Name FROM scope()')[0]['Name'] == custom
            result, base, logs, messages, uploads = collect('F.Success', artifact=custom)
            assert len(uploads) == expected_uploads, messages
            if label == 'nested_output':
                assert (base/'uploads/auto/case-0/scriptblock-logs/nested/test.ps1').read_text().strip() == 'nested'
                assert not any(row['Level']=='ERROR' for row in logs)
            else:
                assert any(row['Level']=='ERROR' for row in logs), messages
            report[label] = dict(flow_id=result, uploads=len(uploads))
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
