#!/usr/bin/env python3
"""Black-box Axon tests: real binary, HTTP, durable state."""
import concurrent.futures
import json
import selectors
import ssl
import http.server
import threading
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else 'build/common-debug/axon').resolve())

class AxonTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='axon-test-')
        self.root = Path(self.temp.name)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            self.port = sock.getsockname()[1]
        self.env = dict(os.environ, AXON_HOME=str(self.root / 'config'), AXON_SERVER=f'http://127.0.0.1:{self.port}')
        self.env.pop('AXON_PRINCIPAL', None)
        self.env.pop('AXON_KEY', None)
        self.call('init', '--data', str(self.root / 'data'), '--admin', 'human:test', '--server', self.env['AXON_SERVER'])
        self.start()

    def start(self, *extra):
        self.local_executor = "--no-executors" not in extra
        self.log = open(self.root / 'server.log', 'ab')
        self.server = subprocess.Popen([BINARY, 'serve', '--data', str(self.root / 'data'), '--listen', f'127.0.0.1:{self.port}', *extra], env=self.env, stdout=self.log, stderr=self.log)
        for _ in range(100):
            try:
                urllib.request.urlopen(self.env['AXON_SERVER'] + '/health', timeout=.2,
                                       context=ssl.create_default_context(cafile=self.env['AXON_CA_BUNDLE'])
                                       if 'AXON_CA_BUNDLE' in self.env else None).close()
                return
            except OSError:
                if self.server.poll() is not None:
                    self.fail((self.root / 'server.log').read_text())
                time.sleep(.03)
        self.fail('server startup timeout')

    def stop(self):
        self.server.terminate()
        self.server.wait(timeout=10)
        self.log.close()
        self.assertEqual(self.server.returncode, 0, (self.root / 'server.log').read_text())

    def tearDown(self):
        if self.server.poll() is None:
            self.stop()
        self.temp.cleanup()

    def call(self, *args, input=None, env=None, ok=True, raw=False):
        result = subprocess.run([BINARY, *args], input=input, env=env or self.env, capture_output=True, timeout=20)
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        else:
            self.assertNotEqual(result.returncode, 0)
        if raw or not ok:
            return result
        return json.loads(result.stdout)

    def fork(self, **kwargs):
        return self.call('fork', **kwargs)['id']

    def write(self, ws, path, text, **kwargs):
        return self.call('write', ws, path, '-', input=text if isinstance(text, bytes) else text.encode(), **kwargs)

    def land(self, ws, **kwargs):
        stack = self.call('stack', ws, '--title', 'test change', '--land', **kwargs)
        deadline = time.monotonic() + 10
        while (self.local_executor and stack['status'] == 'blocked'
               and any(r['kind'] == 'tests' and r['status'] == 'missing'
                       for r in stack.get('requirements', []))):
            self.assertLess(time.monotonic(), deadline, 'local executor did not finish')
            time.sleep(.05)
            stack = self.call('status', stack['id'], **kwargs)
        return stack

    def seed(self):
        ws = self.fork()
        self.write(ws, 'a/file.txt', 'one\ntwo\nthree\nfour\nfive\n')
        self.assertEqual(self.land(ws)['status'], 'landed')

    def test_roundtrip_restart_and_binary(self):
        ws = self.fork()
        data = bytes(range(256)) * 1024
        self.write(ws, 'dir/blob', data)
        self.assertEqual(self.call('cat', ws, 'dir/blob', raw=True).stdout, data)
        stack = self.land(ws)
        self.assertEqual(stack['status'], 'landed')
        self.stop()
        with (self.root / 'data/journal.jsonl').open('ab') as stream:
            stream.write(b'{"torn":')
        self.start()
        self.assertEqual(self.call('get', 'trunk', 'dir/blob', raw=True).stdout, data)
        self.assertEqual(self.call('status', stack['id'])['status'], 'landed')
        self.call('get', 'trunk@0', 'dir/blob', ok=False)

    def test_occ_fast_rebase_merge_conflict(self):
        self.seed()
        a, b = self.fork(), self.fork()
        self.call('cat', b, 'a/file.txt', raw=True)
        self.write(a, 'a/file.txt', 'ONE\ntwo\nthree\nfour\nfive\n')
        self.assertEqual(self.land(a)['route'], 'fast')
        self.write(b, 'b/file.txt', 'independent')
        self.assertEqual(self.land(b)['route'], 'rebase')
        a, b = self.fork(), self.fork()
        self.write(a, 'a/file.txt', 'FIRST\ntwo\nthree\nfour\nfive\n')
        self.write(b, 'a/file.txt', 'ONE\ntwo\nthree\nfour\nLAST\n')
        self.land(a)
        merged = self.land(b)
        self.assertEqual((merged['status'], merged['route']), ('landed', 'merge'))
        self.assertEqual(self.call('get', 'trunk', 'a/file.txt', raw=True).stdout, b'FIRST\ntwo\nthree\nfour\nLAST\n')
        a, b = self.fork(), self.fork()
        self.write(a, 'a/file.txt', 'conflict A\n')
        self.write(b, 'a/file.txt', 'conflict B\n')
        self.land(a)
        conflict = self.land(b)
        self.assertEqual(conflict['status'], 'conflicted')
        resolved = self.call('resolve', conflict['id'])['id']
        self.assertIn(b'<<<<<<<', self.call('cat', resolved, 'a/file.txt', raw=True).stdout)
        self.write(resolved, 'a/file.txt', 'resolved\n')
        self.assertEqual(self.call('stack', resolved, '--title', 'resolve', '--supersedes', conflict['id'], '--land')['status'], 'landed')
        self.assertEqual(self.call('status', conflict['id'])['status'], 'superseded')

    def test_review_ownership_and_auth(self):
        issued = self.call('agent-key', 'bot', raw=True).stdout.decode()
        agent_env = dict(self.env)
        import shlex
        for line in issued.splitlines():
            key, value = line.removeprefix('export ').split('=', 1)
            agent_env[key] = shlex.split(value)[0]
        ws = self.fork(env=agent_env)
        self.write(ws, 'src/code.txt', 'agent code', env=agent_env)
        stack = self.land(ws, env=agent_env)
        self.assertEqual(stack['status'], 'blocked')
        self.call('review', stack['id'], env=agent_env, ok=False)
        self.assertEqual(self.call('review', stack['id'])['status'], 'landed')
        ws = self.fork(env=agent_env)
        self.write(ws, 'docs/readme', 'docs', env=agent_env)
        self.assertEqual(self.land(ws, env=agent_env)['status'], 'landed')
        wrong = dict(agent_env, AXON_KEY=str(self.root / 'wrong.key'))
        (self.root / 'wrong.key').write_text('01' * 32)
        self.call('whoami', env=wrong, ok=False)
        own = self.fork()
        self.call('write', own, 'x', '-', input=b'x', env=agent_env, ok=False)

    def test_build_gates_closure_and_cache(self):
        ws = self.fork()
        self.write(ws, 'pkg/input', 'PASS\n')
        build = {'targets': [{'name': 'test', 'kind': 'test', 'srcs': ['input'], 'cmd': 'grep -q PASS pkg/input'}]}
        self.write(ws, 'pkg/BUILD.axon', json.dumps(build))
        stack = self.land(ws)
        self.assertEqual(stack['status'], 'landed')
        self.assertTrue(self.call('green')['green'])
        receipt = next(e['data'] for e in self.call('events') if e['kind'] == 'executor_receipt')
        signature = receipt.pop('signature')
        receipt.pop('id')
        (self.root / 'receipt.pub').write_bytes(bytes.fromhex('302a300506032b6570032100' + receipt['key']))
        (self.root / 'receipt.sig').write_bytes(bytes.fromhex(signature))
        (self.root / 'receipt.json').write_text(json.dumps(receipt, sort_keys=True, separators=(',', ':')))
        verification = subprocess.run(['openssl', 'pkeyutl', '-verify', '-rawin', '-pubin', '-keyform', 'DER',
                                       '-inkey', str(self.root / 'receipt.pub'), '-sigfile', str(self.root / 'receipt.sig'),
                                       '-in', str(self.root / 'receipt.json')], capture_output=True)
        self.assertEqual(verification.returncode, 0, verification.stderr.decode())
        closure = self.call('closure', '//pkg:test')
        self.assertEqual(set(closure['files']), {'pkg/input', 'pkg/BUILD.axon'})
        destination = self.root / 'materialized'
        self.call('materialize', '//pkg:test', str(destination))
        self.assertEqual((destination / 'pkg/input').read_text(), 'PASS\n')
        ws = self.fork()
        self.write(ws, 'pkg/input', 'FAIL\n')
        self.assertEqual(self.land(ws)['status'], 'blocked')
        self.assertEqual(self.call('get', 'trunk', 'pkg/input', raw=True).stdout, b'PASS\n')
        self.assertEqual(self.call('affected', 'pkg/input'), ['//pkg:test'])

    def test_build_does_not_hold_request_lock(self):
        marker = self.root / 'build-started'
        release = self.root / 'release-build'
        ws = self.fork()
        command = f'touch {marker}; while [ ! -f {release} ]; do sleep .05; done'
        self.write(ws, 'BUILD.axon', json.dumps({'targets': [
            {'name': 'test', 'kind': 'test', 'cmd': command}]}))
        stack = self.call('stack', ws, '--title', 'slow build', '--land')
        self.assertEqual(stack['status'], 'blocked')
        deadline = time.monotonic() + 5
        while not marker.exists():
            self.assertLess(time.monotonic(), deadline, 'executor did not start')
            time.sleep(.02)
        executor = concurrent.futures.ThreadPoolExecutor()
        try:
            future = executor.submit(self.fork)
            other = future.result(timeout=2)
            self.write(other, 'independent', 'still responsive')
        finally:
            release.touch()
            executor.shutdown()
        self.assertEqual(self.call('land', stack['id'], '--wait', '--timeout', '5')['status'], 'landed')

    def test_paths_listing_moves_lines(self):
        self.seed()
        ws = self.fork()
        self.call('ls', ws, 'a')
        self.assertIn('a/', self.call('ws', 'reads', ws))
        self.call('write', ws, '../escape', '-', input=b'x', ok=False)
        self.call('write', ws, '/absolute', '-', input=b'x', ok=False)
        self.call('mv', ws, 'a', 'b')
        self.assertEqual(self.land(ws)['status'], 'landed')
        self.assertIn('file.txt', self.call('get', 'trunk', 'b'))
        self.call('line', 'create', 'release', '--from', 'trunk@1')
        self.assertIn('a', self.call('get', 'release', '.'))
        ws = self.fork()
        self.call('rm', ws, 'b')
        self.assertEqual(self.land(ws)['status'], 'landed')
        self.assertEqual(self.call('get', 'trunk', '.'), {})

    def test_missing_reads_and_git_roundtrip(self):
        ws = self.fork()
        self.call('cat', ws, 'missing', ok=False)
        self.assertIn('missing', self.call('ws', 'reads', ws))
        repo = self.root / 'git-source'
        repo.mkdir()
        def git(*args):
            return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.DEVNULL).decode().strip()
        git('init')
        git('config', 'user.name', 'Test')
        git('config', 'user.email', 'test@example.test')
        (repo / 'file with spaces').write_bytes(b'hello\x00binary')
        (repo / 'executable').write_text('#!/bin/sh\necho hi\n')
        (repo / 'executable').chmod(0o755)
        (repo / 'link').symlink_to('file with spaces')
        git('add', '.')
        git('commit', '-m', 'initial')
        (repo / 'next').write_text('second')
        git('add', '.')
        git('commit', '-m', 'second')
        expected = git('rev-parse', 'HEAD^{tree}')
        result = self.call('git', 'import', '--repo', str(repo))
        self.assertEqual(len(result), 2)
        self.assertTrue(all(stack['status'] == 'landed' for stack in result))
        self.call('git', 'export', '--repo', str(repo))
        self.assertEqual(git('rev-parse', 'axon/trunk^{tree}'), expected)
        self.assertEqual(git('log', '--format=%an <%ae> %at %ai', 'HEAD'),
                         git('log', '--format=%an <%ae> %at %ai', 'axon/trunk'))
        self.assertTrue(all('skipped' in item for item in self.call('git', 'import', '--repo', str(repo))))

    def test_offline_spool_and_replay_after_restart(self):
        ws = self.fork()
        self.stop()
        queued = self.call('write', ws, 'offline', '-', '--offline', input=b'offline content')
        self.assertEqual(queued['pending'], 1)
        self.call('mv', ws, 'offline', 'renamed', '--offline')
        spool = self.root / 'config' / 'spool.json'
        original = spool.read_bytes()
        self.start('--no-executors')
        self.assertEqual(self.call('replay')['replayed'], 2)
        self.assertEqual(self.call('cat', ws, 'renamed', raw=True).stdout, b'offline content')
        self.stop()
        spool.write_bytes(original)  # Simulate a crash before acknowledged entries were removed.
        self.start('--no-executors')
        self.assertEqual(self.call('replay')['replayed'], 2)
        status = self.call('ws', 'status', ws)
        self.assertEqual(len(status['workspace']['drafts']), 2)
        self.assertEqual(self.call('admin', 'prune', '--age', '1s', '--keep', '1', '--dry-run')['dry_run'], True)

    def test_symbol_reads_and_declaration_merge(self):
        ws = self.fork()
        self.write(ws, 'code.cpp', 'int a(){return 1;} int b(){return 2;}\n')
        self.land(ws)
        left, right = self.fork(), self.fork()
        self.assertIn(b'int a()', self.call('symbol', left, 'code.cpp', 'a', raw=True).stdout)
        self.write(left, 'code.cpp', 'int a(){return 3;} int b(){return 2;}\n')
        self.write(right, 'code.cpp', 'int a(){return 1;} int b(){return 4;}\n')
        self.land(right)
        self.assertEqual(self.land(left)['status'], 'landed')
        self.assertEqual(self.call('get', 'trunk', 'code.cpp', raw=True).stdout,
                         b'int a(){return 3;} int b(){return 4;}\n')

    def test_subscription_admission_limit(self):
        self.fork()
        streams = [subprocess.Popen([BINARY, 'subscribe'], env=self.env, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE) for _ in range(2)]
        try:
            for stream in streams:
                with selectors.DefaultSelector() as selector:
                    selector.register(stream.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(timeout=5), 'subscription did not begin')
                    self.assertTrue(stream.stdout.readline())
            rejected = self.call('subscribe', ok=False)
            self.assertIn(b'subscription limit', rejected.stderr)
            self.assertEqual(self.call('whoami')['principal'], 'human:test')
        finally:
            for stream in streams:
                stream.terminate()
                stream.wait(timeout=5)
                stream.stdout.close()
                stream.stderr.close()

    def test_workspace_workflow_trigger(self):
        self.stop()
        self.start('--no-executors')
        workflows = self.root / 'workflows.json'
        workflows.write_text(json.dumps([{'name': 'edited', 'on': 'workspace_changed', 'kind': 'lint'}]))
        self.call('admin', 'workflows', str(workflows))
        ws = self.fork()
        self.write(ws, 'BUILD.axon', json.dumps({'targets': [{'name': 'lint', 'kind': 'lint', 'srcs': ['input'], 'cmd': 'true'}]}))
        self.write(ws, 'input', 'value')
        claim = self.call('executor', '--once', '--work', str(self.root))
        completion = claim['completion'].copy()
        completion.pop('id')
        signature = completion.pop('signature')
        (self.root / 'completion.json').write_text(json.dumps(completion, sort_keys=True, separators=(',', ':')))
        (self.root / 'completion.sig').write_bytes(bytes.fromhex(signature))
        (self.root / 'completion.der').write_bytes(bytes.fromhex('302a300506032b6570032100' + completion['key']))
        verify = subprocess.run(['openssl', 'pkeyutl', '-verify', '-rawin', '-pubin', '-keyform', 'DER',
                                 '-inkey', str(self.root / 'completion.der'), '-in', str(self.root / 'completion.json'),
                                 '-sigfile', str(self.root / 'completion.sig')], capture_output=True)
        self.assertEqual(verify.returncode, 0, verify.stderr)

    def test_remote_executor_and_flaky_attestations(self):
        self.stop()
        self.start('--no-executors')
        ws = self.fork()
        self.write(ws, 'input', 'PASS')
        self.write(ws, 'BUILD.axon', json.dumps({'targets': [{'name': 'test', 'srcs': ['input'], 'cmd': 'grep -q PASS input'}]}))
        stack = self.land(ws)
        self.assertEqual(stack['status'], 'blocked')
        self.call('executor', '--once', '--work', str(self.root))
        self.assertEqual(self.call('status', stack['id'])['status'], 'landed')
        closure = self.call('closure', '//:test')
        def attest(result):
            self.call('attest', '--target', '//:test', '--input', closure['input_hash'], '--kind', 'tests', '--result', result)
        attest('failed')
        self.assertIn(b'flaky', self.call('green', ok=False).stdout)
        attest('passed')
        attest('passed')
        self.call('green', ok=False)
        attest('passed')
        self.assertTrue(self.call('green')['green'])

    def test_diff_wait_and_policy(self):
        ws = self.fork()
        self.write(ws, 'docs/file', 'hello\n')
        stack = self.call('stack', ws, '--title', 'docs')
        self.assertIn(b'+hello', self.call('diff', stack['id'], raw=True).stdout)
        self.assertEqual(self.call('land', stack['id'], '--wait', '--timeout', '2')['status'], 'landed')
        policy = self.root / 'policy.json'
        policy.write_text(json.dumps({'rules': [{'name': 'protected', 'when': {'any_path': ['secret/**']}, 'deny': 'protected path'}]}))
        self.call('admin', 'policy', str(policy))
        ws = self.fork()
        self.write(ws, 'secret/key', 'not allowed')
        self.assertEqual(self.land(ws)['status'], 'rejected')

    def test_parallel_disjoint_writers(self):
        workspaces = [self.fork() for _ in range(8)]
        def writer(pair):
            index, ws = pair
            self.write(ws, f'domain{index}/file', f'{index}')
            return self.land(ws)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(writer, enumerate(workspaces)))
        self.assertTrue(all(result['status'] == 'landed' for result in results))
        self.assertEqual(len(self.call('get', 'trunk', '.')), 8)
        self.assertEqual(len(self.call('log')), 9)

    def test_cache_tier(self):
        ws = self.fork()
        content = b'cached CAS payload 12345'
        stored = self.write(ws, 'cached.txt', content)
        stack = self.land(ws)
        self.assertEqual(stack['status'], 'landed')
        snap = self.call('get', 'trunk', 'cached.txt', raw=True)
        self.assertEqual(snap.stdout, content)

        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            cache_port = sock.getsockname()[1]

        cache_dir = self.root / 'cache-tier'
        cache_log = open(self.root / 'cache.log', 'ab')
        cache_proc = subprocess.Popen([BINARY, 'cache', '--upstream', self.env['AXON_SERVER'],
                                      '--listen', f'127.0.0.1:{cache_port}', '--dir', str(cache_dir)],
                                      env=self.env, stdout=cache_log, stderr=cache_log)
        try:
            for _ in range(50):
                try:
                    urllib.request.urlopen(f'http://127.0.0.1:{cache_port}/cache/stats', timeout=.2).close()
                    break
                except OSError:
                    time.sleep(.05)

            cas_url = f'http://127.0.0.1:{cache_port}/cas/' + stored['entry']['hash']
            with urllib.request.urlopen(cas_url) as response:
                self.assertEqual(response.read(), content)
                self.assertEqual(response.headers['X-Axon-Cache'], 'miss')
            with urllib.request.urlopen(cas_url) as response:
                self.assertEqual(response.read(), content)
                self.assertEqual(response.headers['X-Axon-Cache'], 'hit')
            health_req = urllib.request.urlopen(f'http://127.0.0.1:{cache_port}/health')
            self.assertEqual(health_req.status, 200)

            stats_req = urllib.request.urlopen(f'http://127.0.0.1:{cache_port}/cache/stats')
            self.assertEqual(stats_req.status, 200)
            stats_text = stats_req.read().decode()
            self.assertIn('hits', stats_text)
            self.assertIn('misses', stats_text)
        finally:
            cache_proc.terminate()
            cache_proc.wait(timeout=5)
            cache_log.close()

    def test_native_tls(self):
        self.stop()
        certificate = self.root / 'cert.pem'
        key = self.root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(certificate), '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'],
                       check=True, capture_output=True)
        self.env['AXON_SERVER'] = f'https://127.0.0.1:{self.port}'
        self.env['AXON_CA_BUNDLE'] = str(certificate)
        self.start('--tls-cert', str(certificate), '--tls-key', str(key))
        self.assertEqual(self.call('whoami')['principal'], 'human:test')
        untrusted = dict(self.env)
        untrusted.pop('AXON_CA_BUNDLE')
        self.call('whoami', env=untrusted, ok=False)
        ws = self.fork()
        self.write(ws, 'tls.txt', 'encrypted transport')
        self.assertEqual(self.land(ws)['status'], 'landed')
        cursor = self.call('events')[-1]['offset'] + 1
        stream = subprocess.Popen([BINARY, 'subscribe', '--from', str(cursor)], env=self.env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            # A normal stream closes after 30 seconds and must reconnect over TLS.
            time.sleep(31)
            self.assertIsNone(stream.poll(), 'TLS subscription failed at renewal')
            self.fork()
            with selectors.DefaultSelector() as selector:
                selector.register(stream.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(5), 'TLS stream did not resume')
                self.assertEqual(json.loads(stream.stdout.readline())['kind'], 'workspace_forked')
        finally:
            stream.terminate()
            stream.communicate(timeout=5)

    def test_cache_rejects_corrupt_upstream(self):
        class WrongContent(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'wrong content')
            def log_message(self, *args):
                pass
        upstream = http.server.HTTPServer(('127.0.0.1', 0), WrongContent)
        thread = threading.Thread(target=upstream.serve_forever)
        thread.start()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        process = subprocess.Popen([BINARY, 'cache', '--upstream', f'http://127.0.0.1:{upstream.server_port}',
                                    '--listen', f'127.0.0.1:{port}', '--dir', str(self.root / 'bad-cache')],
                                   env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 5
            while True:
                try:
                    urllib.request.urlopen(f'http://127.0.0.1:{port}/cache/stats', timeout=.2).close()
                    break
                except OSError:
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(.03)
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(f'http://127.0.0.1:{port}/cas/' + '0' * 64)
            self.assertEqual(error.exception.code, 502)
            error.exception.close()
        finally:
            process.terminate()
            process.wait(timeout=5)
            upstream.shutdown()
            thread.join()
            upstream.server_close()

    def test_log_limit_and_admin_workflows(self):
        for i in range(5):
            ws = self.fork()
            self.write(ws, f'logtest/{i}.txt', f'{i}')
            self.land(ws)
        full_log = self.call('log')
        self.assertGreaterEqual(len(full_log), 5)
        limited = self.call('log', '--limit', '2')
        self.assertEqual(len(limited), 2)

        wfs = self.call('admin', 'workflows')
        self.assertTrue(isinstance(wfs, list))
        self.assertEqual(wfs[0]['name'], 'tests')

        new_wfs = [{'name': 'custom_ci', 'on': 'head_moved', 'kind': 'lint'}]
        wf_file = self.root / 'workflows.json'
        wf_file.write_text(json.dumps(new_wfs))
        updated = self.call('admin', 'workflows', str(wf_file))
        self.assertEqual(updated, new_wfs)
        self.assertEqual(self.call('admin', 'workflows'), new_wfs)

    def test_queue_and_agent_ejection(self):
        issued = self.call('agent-key', 'ci_agent', raw=True).stdout.decode()
        agent_env = dict(self.env)
        import shlex
        for line in issued.splitlines():
            if line.startswith('export '):
                key, value = line.removeprefix('export ').split('=', 1)
                agent_env[key] = shlex.split(value)[0]

        ws = self.fork()
        self.write(ws, 'ci/data', 'PASS\n')
        self.write(ws, 'ci/BUILD.axon', json.dumps({'targets': [{'name': 'chk', 'kind': 'test', 'srcs': ['data'], 'cmd': 'grep -q PASS ci/data'}]}))
        self.assertEqual(self.land(ws)['status'], 'landed')

        aws = self.fork(env=agent_env)
        self.write(aws, 'ci/data', 'BROKEN\n', env=agent_env)
        stack = self.land(aws, env=agent_env)
        self.assertEqual(stack['status'], 'ejected')
        self.assertIn('fails with this stack', stack['reason'])

        q = self.call('queue')
        self.assertTrue(isinstance(q, list))

    def test_workflow_gates_and_post_landing_jobs(self):
        workflow = self.root / 'workflows.json'
        workflow.write_text(json.dumps([{'name': 'lint', 'on': 'head_moved', 'kind': 'lint', 'gate': True}]))
        self.call('admin', 'workflows', str(workflow))
        ws = self.fork()
        self.write(ws, 'BUILD.axon', json.dumps({'targets': [
            {'name': 'lint', 'kind': 'lint', 'srcs': ['input'], 'cmd': 'grep -q PASS input'}]}))
        self.write(ws, 'input', 'PASS')
        stack = self.call('stack', ws, '--title', 'lint gate', '--wait', '--timeout', '5')
        self.assertEqual(stack['status'], 'landed')
        workflow.write_text(json.dumps([{'name': 'lint', 'on': 'head_moved', 'kind': 'lint', 'gate': False}]))
        self.call('admin', 'workflows', str(workflow))
        ws = self.fork()
        self.write(ws, 'input', 'FAIL')
        stack = self.land(ws)
        self.assertEqual(stack['status'], 'landed')
        deadline = time.monotonic() + 5
        while True:
            events = self.call('events')
            if any(e['kind'] == 'attestation' and e['data']['kind'] == 'lint'
                   and e['data']['result'] == 'failed' for e in events):
                break
            self.assertLess(time.monotonic(), deadline, 'post-landing workflow did not run')
            time.sleep(.05)
        broken = [e for e in events if e['kind'] == 'target_broken']
        self.assertEqual(broken[-1]['data']['stack'], stack['id'])
        self.call('green', ok=False)

    def test_speculative_queue_candidates(self):
        ws = self.fork()
        self.write(ws, 'BUILD.axon', json.dumps({'targets': [
            {'name': 'test', 'srcs': ['*.txt'], 'cmd': 'true'}]}))
        self.assertEqual(self.land(ws)['status'], 'landed')
        self.stop()
        self.start('--no-executors')
        first, second = self.fork(), self.fork()
        self.write(first, 'a.txt', 'a')
        self.write(second, 'b.txt', 'b')
        a, b = self.land(first), self.land(second)
        self.assertEqual(a['status'], 'blocked')
        self.assertEqual(b['status'], 'blocked')
        queued = [self.call('status', a['id']), self.call('status', b['id'])]
        self.assertTrue(any('speculative_root' in stack for stack in queued))
        for _ in range(5):
            self.call('executor', '--once', '--work', str(self.root))
            queued = [self.call('status', a['id']), self.call('status', b['id'])]
            if all(stack['status'] == 'landed' for stack in queued):
                break
        self.assertTrue(all(stack['status'] == 'landed' for stack in queued))
        self.assertEqual(self.call('get', 'trunk', 'a.txt', raw=True).stdout, b'a')
        self.assertEqual(self.call('get', 'trunk', 'b.txt', raw=True).stdout, b'b')

    def test_event_stream_pushes_new_events(self):
        events = self.call('events')
        cursor = events[-1]['offset'] + 1 if events else 0
        process = subprocess.Popen([BINARY, 'subscribe', '--from', str(cursor)],
                                   env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            # The event may precede stream establishment; durable cursor replay covers both orders.
            self.fork()
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(5), 'stream did not push the new event')
                event = json.loads(process.stdout.readline())
            self.assertEqual(event['kind'], 'workspace_forked')
            self.assertGreaterEqual(event['offset'], cursor)
        finally:
            process.terminate()
            process.communicate(timeout=5)

    def test_admin_compact_and_invalid_policy(self):
        self.seed()
        path = self.root / 'policy.json'
        original = self.call('admin', 'policy')
        path.write_text(json.dumps({'rules': [{'name': 'typo', 'when': {'any_paths': ['secret/**']}}]}))
        self.call('admin', 'policy', str(path), ok=False)
        self.assertEqual(self.call('admin', 'policy'), original)
        self.assertTrue(self.call('admin', 'compact')['compacted'])
        self.stop()
        self.start()
        self.assertEqual(self.call('get', 'trunk', 'a/file.txt', raw=True).stdout,
                         b'one\ntwo\nthree\nfour\nfive\n')

    def test_metrics_and_events_partition(self):
        self.seed()
        metrics = urllib.request.urlopen(self.env['AXON_SERVER'] + '/metrics').read().decode()
        self.assertIn('axon_landings_total', metrics)
        self.assertIn('axon_landings_fast_path_total', metrics)
        self.assertIn('axon_landings_total', metrics)

        evs = self.call('events', 'line-trunk')
        self.assertTrue(isinstance(evs, list))
        self.assertGreater(len(evs), 0)

        self.call('events', 'line-trunk', '--group', 'g1', '--commit', '1')
        from_commit = self.call('events', 'line-trunk', '--group', 'g1')
        self.assertTrue(isinstance(from_commit, list))

    def test_web_view_proxies_allowlisted_reads(self):
        self.seed()
        web = subprocess.Popen([BINARY, 'web', '--listen', '127.0.0.1:0'], env=self.env,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        try:
            url = web.stdout.readline().strip()
            base, token = url.split('/#token=')

            def api(body, token=token, host=None):
                headers = {'Content-Type': 'application/json', 'X-Axon-Token': token}
                if host:
                    headers['Host'] = host
                request = urllib.request.Request(base + '/api', json.dumps(body).encode(), headers)
                try:
                    with urllib.request.urlopen(request, timeout=5) as response:
                        return response.status, json.loads(response.read())
                except urllib.error.HTTPError as error:
                    return error.code, json.loads(error.read())

            self.assertIn(b'<title>Axon</title>', urllib.request.urlopen(base + '/', timeout=5).read())
            status, file = api({'command': 'get', 'args': ['trunk', 'a/file.txt']})
            self.assertEqual((status, file['kind'], file['text']), (200, 'file', 'one\ntwo\nthree\nfour\nfive\n'))
            status, listing = api({'command': 'get', 'args': ['trunk', '']})
            self.assertEqual(listing['kind'], 'dir')
            self.assertIn('a', listing['entries'])
            self.assertEqual(len(api({'command': 'log', 'options': {'limit': '1'}})[1]), 1)
            self.assertEqual(api({'command': 'write', 'args': ['ws', 'x']})[0], 400)
            self.assertEqual(api({'command': 'status', 'options': {'request': 'true'}})[0], 400)
            self.assertEqual(api({'command': 'lines'}, token='0' * 32)[0], 403)
            self.assertEqual(api({'command': 'lines'}, host='attacker.example')[0], 403)
        finally:
            web.terminate()
            web.wait(timeout=10)
        self.call('web', '--listen', '0.0.0.0:0', ok=False)

if __name__ == '__main__':
    unittest.main(verbosity=2)
