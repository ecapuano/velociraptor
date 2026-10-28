#!/usr/bin/env python3
"""Run only existing real-client/installed-monitor compatibility cases.

Uses review_compatibility.py arguments. The legacy Linux resource-limit checks
are excluded so their immediate-cleanup assertion cannot block this independent
compatibility check. No analyzer or monitor YAML is altered.
"""
import inspect
import linux_extended
import review_compatibility

source = inspect.getsource(linux_extended.exercise)
start = source.index('    for label, replacement, limits in [')
end = source.index('    # Install the actual SERVER_EVENT', start)
# The installed timeout monitor references this isolated test-only analyzer.
fixture = '''    timeout_name = 'Custom.Test.timeout'
    timeout = original.replace('name: '+NAME, 'name: '+timeout_name, 1)
    timeout, changed = re.subn(r'execve\\(argv=\\[HBExe,.*?\\],', lambda _: 'execve(argv=["/bin/sleep", "120"],', timeout, count=1, flags=re.S)
    assert changed == 1
    install(timeout_name, timeout)

'''
exec(compile(source[:start]+fixture+source[end:], __file__, 'exec'), linux_extended.__dict__)

if __name__ == '__main__':
    review_compatibility.main()
