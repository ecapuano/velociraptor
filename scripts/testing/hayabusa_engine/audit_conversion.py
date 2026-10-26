#!/usr/bin/env python3
"""Audit a pinned curated package; reports omissions, not detection accuracy."""
import argparse
import collections
import hashlib
import io
import json
import urllib.request
import zipfile
from pathlib import Path

URL = 'https://sigma.velocidex.com/artifacts/Velociraptor-Hayabusa-Rules.zip'
SHA256 = 'a9c2909cf701b64545fbead387faf7af55860b42d0ae1512f707fda81be79814'
RULE_ID = b'46614e82-7926-41f9-85aa-006b98c5c2a3'
RULE_PATH = ('hayabusa/hayabusa/builtin/Security/LogonLogoff/Logon/'
             'Sec_4624_Med_Logon-Type9-NewInteractive_PossibleTokenImpersonation.yml')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--zip', type=Path, help='Existing curated ZIP')
    source.add_argument('--download', action='store_true', help='Fetch the documented URL')
    args = parser.parse_args()
    if args.download:
        with urllib.request.urlopen(URL, timeout=60) as response:
            data = response.read()
    else:
        data = args.zip.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        parser.error(f'Package changed: expected {SHA256}, got {digest}. '
                     'Review the new package separately; do not reuse recorded conclusions.')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        rejects = json.loads(archive.read('rejected.json'))['Rejects']
        rules = [name for name in archive.namelist()
                 if name.startswith('rules/') and not name.endswith('/')]
        report = {
            'source': URL,
            'sha256': digest,
            'converted_rule_files': len(rules),
            'reject_diagnostics': len(rejects),
            'rejected_unique_paths': len({row['Path'] for row in rejects}),
            'reject_errors': dict(collections.Counter(row['Error'] for row in rejects)),
            'token_impersonation_rule_id': RULE_ID.decode(),
            'token_impersonation_rejections': [row for row in rejects
                                               if row['Path'] == RULE_PATH],
            'token_impersonation_present_in_converted_rules': any(
                RULE_ID in archive.read(name) for name in rules),
            'limits': 'Static package audit only. Rejection counts are not missed detections. '
                      'Some rejected rules are deprecated or unsupported. No speed comparison.',
        }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
