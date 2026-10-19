import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

// No host registration/container/credentials: exercise only output handling with a
// synthetic trusted-pattern seam, as if an operator had installed reviewed bytes.
test('broker quarantines read, command and export output before serializing it', () => {
  const script = String.raw`
import importlib.util, io, json, re, sys
from contextlib import redirect_stdout
spec = importlib.util.spec_from_file_location('runtime', '.agent-guard/runtime.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
runtime.output_patterns = lambda: [re.compile('SYNTHETIC_INJECTION_CANARY')]
policy = {'secret_paths': [], 'quarantine_paths': [], 'protected_write_paths': []}
config = {'policy': policy, 'image': 'synthetic-not-executed'}
for tool, args in [('execute', {'command': 'synthetic'}), ('read_file', {'path': 'synthetic.txt'}), ('export_changes', {})]:
    runtime.execute = lambda *a, **k: (0, 'SYNTHETIC_INJECTION_CANARY')
    runtime.read_file = lambda *a, **k: {'text': 'SYNTHETIC_INJECTION_CANARY', 'sha256': 'synthetic'}
    runtime.snapshot = lambda *a, **k: (b'', {'synthetic.txt': (b'SYNTHETIC_INJECTION_CANARY', 0o600)})
    request = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': tool, 'arguments': args}}
    sys.stdin = io.StringIO(json.dumps(request) + '\n')
    output = io.StringIO()
    with redirect_stdout(output): runtime.serve_session('/synthetic', config, {})
    response = output.getvalue()
    assert 'SYNTHETIC_INJECTION_CANARY' not in response, tool
    assert json.loads(response)['result']['isError'], tool
assert runtime.checked_output({'text': 'ordinary source text'})['text'] == 'ordinary source text'
try: runtime.checked_output({'text': 'x' * (runtime.MAX_OUTPUT + 1)})
except runtime.Refused: pass
else: raise AssertionError('oversize output escaped')
`;
  const result = spawnSync('python3', ['-I', '-c', script], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
});

test('missing trusted output policy fails closed', () => {
  const script = String.raw`
import importlib.util
spec = importlib.util.spec_from_file_location('runtime', '.agent-guard/runtime.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
runtime.protected_install = lambda path: (_ for _ in ()).throw(OSError('synthetic absent installation'))
try: runtime.checked_output('ordinary source text')
except runtime.Refused as e: assert str(e) == 'trusted output policy unavailable'
else: raise AssertionError('missing policy allowed output')
`;
  const result = spawnSync('python3', ['-I', '-c', script], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
});


test('CLI failure paths never echo workload output or hostile filenames', () => {
  const script = String.raw`
import importlib.util, io, sys
from contextlib import redirect_stdout, redirect_stderr
spec = importlib.util.spec_from_file_location('runtime', '.agent-guard/runtime.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
runtime.registration = lambda root: ('/synthetic', {'policy': {}, 'image': 'synthetic', 'checks': {'stop': 'synthetic'}})
for operation, argument in [('preflight', None), ('execute', 'synthetic'), ('check', 'stop')]:
    for message in ['workload failed: SYNTHETIC_INJECTION_CANARY', 'unsafe file: SYNTHETIC_INJECTION_CANARY']:
        runtime.execute = lambda *a, **k: (_ for _ in ()).throw(runtime.Refused(message))
        sys.argv = ['runtime', operation] + ([argument] if argument else [])
        sys.stdin = io.StringIO('')
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr): code = runtime.main()
        assert code == 2
        assert 'SYNTHETIC_INJECTION_CANARY' not in stdout.getvalue() + stderr.getvalue()
        assert 'trusted validation did not pass' in stderr.getvalue()
`;
  const result = spawnSync('python3', ['-I', '-c', script], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
});
