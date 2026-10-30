"""Controlled Sigma rules; noisy identity is deliberately from bundled noisy_rules.txt."""
from pathlib import Path
import yaml

RULES = {
    'normal': ('11111111-1111-4111-8111-111111111111', 'stable'),
    'deprecated': ('22222222-2222-4222-8222-222222222222', 'deprecated'),
    'unsupported': ('33333333-3333-4333-8333-333333333333', 'unsupported'),
    # The bundled configuration marks this ID noisy. Its test rule body is ours.
    'noisy': ('b1782e40-d247-4de1-86d1-37392cb62e3b', 'stable'),
}
FLAGS = dict(EnableDeprecatedRules='deprecated', EnableUnsupportedRules='unsupported', EnableNoisyRules='noisy')


def write_rules(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    for label, (identity, status) in RULES.items():
        rule = dict(title='Controlled '+label, id=identity, status=status,
                    description='Integration fixture: any security logon',
                    author='Integration test', date='2026/10/30',
                    logsource=dict(product='windows', service='security'),
                    detection=dict(selection=dict(Channel="Security", EventID=4624), condition='selection'),
                    level='medium')
        (directory/(label+'.yml')).write_text(yaml.safe_dump(rule, sort_keys=False))
    return directory


def exercise_rules(ctx, results):
    from collections import Counter
    rules = write_rules(ctx['work']/'controlled rules')
    cases = [('custom_rules_defaults', {}, {'normal'}),
             *[(flag, {flag: True}, {'normal', label}) for flag, label in FLAGS.items()],
             ('custom_rules_all', {flag: True for flag in FLAGS}, set(RULES)),
             ('custom_rule_file', {}, {'normal'})]
    for label, flags, enabled in cases:
        selected = rules/'normal.yml' if label=='custom_rule_file' else rules
        flow, base, logs, messages, uploads = ctx['collect']('F.Success', overrides=dict(CustomRulesPath=str(selected), **flags))
        rows = ctx['rows_for'](flow)
        status = [row for row in rows if row['Kind']=='Status']
        assert len(status)==1 and status[0]['Success'] is True, status
        counts = dict(Counter(row['RuleID'] for row in rows if row['Kind']=='Detection'))
        assert counts == {RULES[key][0]:583 for key in enabled}, (label, counts)
        results[label] = dict(flow_id=flow, detection_counts=counts, status=status)
    import os
    fifo = ctx['work']/'rules-fifo'
    os.mkfifo(fifo)
    for label, path in [('custom_rules_fifo', str(fifo)), ('custom_rules_missing', str(ctx['work']/'absent-rules')), ('custom_rules_relative', 'controlled-rules')]:
        flow, base, logs, messages, uploads = ctx['collect']('F.Success', overrides=dict(CustomRulesPath=path))
        rows = ctx['rows_for'](flow)
        statuses = [row for row in rows if row['Kind']=='Status']
        assert not any(row.get('Success') for row in statuses), statuses
        assert not uploads and not any(row['Kind']=='Detection' for row in rows), rows
        assert any(row['Level']=='ERROR' for row in logs), logs
        assert 'execve:' not in messages, messages
        results[label] = dict(flow_id=flow, fail_closed=True, status=statuses)
    empty = ctx['work']/'empty-rules'
    empty.mkdir()
    malformed = ctx['work']/'malformed-rule.yml'
    malformed.write_text('detection: [unterminated')
    for label, path in [('custom_rules_empty', empty), ('custom_rules_malformed', malformed)]:
        flow, base, logs, messages, uploads = ctx['collect']('F.Success', overrides=dict(CustomRulesPath=str(path)))
        rows = ctx['rows_for'](flow)
        statuses = [row for row in rows if row['Kind']=='Status']
        assert len(statuses)==1 and statuses[0]['Success'] is False and statuses[0]['EngineSuccess'] is False, statuses
        assert statuses[0]['ReturnCode'] != 0 and not any(row['Kind']=='Detection' for row in rows), rows
        if label=='custom_rules_malformed':
            assert statuses[0]['HasDiagnostics'] is True and any(row['Kind']=='Diagnostic' for row in rows), rows
        results[label] = dict(flow_id=flow, status=statuses, detection_rows=0)
    # An explicit level filter still applies to enabled optional rules. With all
    # controlled rules at medium, high loads no rules and Hayabusa exits nonzero.
    flow, base, logs, messages, uploads = ctx['collect']('F.Success', overrides=dict(CustomRulesPath=str(rules), MinimumLevel='high', **{flag:True for flag in FLAGS}))
    rows = ctx['rows_for'](flow)
    assert not any(row['Kind']=='Detection' for row in rows), rows
    statuses = [row for row in rows if row['Kind']=='Status']
    assert statuses and statuses[0]['Success'] is False, statuses
    results['custom_rules_minimum_level'] = dict(flow_id=flow, status=statuses, detection_rows=0)
    return rules


def cli_baseline():
    """Reproduce option expectations directly, independently of VQL."""
    import argparse
    from collections import Counter
    import json
    import subprocess
    parser = argparse.ArgumentParser(description=cli_baseline.__doc__)
    parser.add_argument('--engine', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--rules-config', type=Path, required=True)
    parser.add_argument('--workdir', type=Path, required=True)
    args = parser.parse_args()
    args.workdir.mkdir(parents=True, exist_ok=False)
    rules = write_rules(args.workdir/'rules').resolve()
    cases = [('default', [], {'normal'}),
             *[(label, ['--enable-'+label+'-rules'], {'normal', label}) for label in FLAGS.values()],
             ('all', ['--enable-'+label+'-rules' for label in FLAGS.values()], set(RULES)),
             ('file', [], {'normal'})]
    report = {}
    for label, flags, enabled in cases:
        output = (args.workdir/(label+'.jsonl')).resolve()
        command = [str(args.engine.resolve()), 'dfir-timeline', '--file', str(args.fixture.resolve()),
                   '--rules', str(rules/'normal.yml' if label=='file' else rules),
                   '--rules-config', str(args.rules_config.resolve()), '--output', str(output),
                   '--output-type', 'jsonl', '--profile', 'verbose', '--no-wizard', '--threads', '2']+flags
        process = subprocess.run(command, cwd=args.engine.resolve().parent, capture_output=True, text=True)
        (args.workdir/(label+'.log')).write_text(process.stdout+process.stderr)
        assert process.returncode == 0, label
        rows = [json.loads(line) for line in output.read_text().splitlines() if line.strip()]
        counts = dict(Counter(row['RuleID'] for row in rows))
        assert counts == {RULES[key][0]:583 for key in enabled}, (label, counts)
        report[label] = dict(returncode=process.returncode, counts=counts)
    (args.workdir/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    cli_baseline()
