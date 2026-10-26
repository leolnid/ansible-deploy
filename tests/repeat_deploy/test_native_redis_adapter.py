import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
MIXIN = ROOT / 'roles/RepeatDeploy/files/s2_native_redis_queue_mixin.py'
ADAPTER = ROOT / 'roles/RepeatDeploy/files/s2_native_redis_queue_adapter.php'
spec = importlib.util.spec_from_file_location('native_redis_mixin', MIXIN)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FakeRelease(module.NativeRedisQueueMixin):
    def __init__(self, root, cache, config):
        self.root = root
        self.queue_cache = cache
        self.p = {'php_cli': r'C:\Development\_tools\php85\php.exe'}
        self.uid = 33
        self.cfg = config
        self.calls = []

    def statuses(self):
        return {'fixture:1': {'state': 'RUNNING', 'pid': 123}}

    def own_queue_pids(self):
        return {123: [b'/php8.5', b'artisan', b'queue:work', b'fixture-redis', b'--queue=main,backfill']}

    def run(self, argv, *, input=None, timeout=20, **kwargs):
        self.calls.append((argv, input))
        if any('s2_native_redis_counts_entry' in str(value) for value in argv):
            return json.dumps({'jobs': 8, 'reserved': 2, 'framework_connection_identity_match': True,
                               'payloads_read': False, 'data_write_commands': 0}).encode()
        return json.dumps({'default': {'host': '127.0.0.1', 'port': 6379,
                                      'database': 4, 'prefix': 'safe-prefix:'}}).encode()


class NativeRedisAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='redis-mixin-fixture-')
        self.root = pathlib.Path(self.tmp.name)
        self.cache = self.root / 'config.php'
        self.cache.write_text('fixed synthetic config', encoding='ascii')
        self.config = {
            'queue': {'default': 'fixture-redis', 'connections': {
                'fixture-redis': {'driver': 'redis', 'connection': 'default', 'queue': 'main'}}},
            'database': {'redis': {'client': 'phpredis', 'default': {
                'host': '127.0.0.1', 'port': 6379, 'database': 4,
                'password': 'synthetic-test-only'}}},
        }
        self.adapter = ADAPTER.read_text(encoding='utf-8')

    def tearDown(self):
        self.tmp.cleanup()

    def test_frozen_queue_scope_and_readonly_count_contract(self):
        app = FakeRelease(self.root, self.cache, self.config)
        app.bind_native_redis_adapter(self.adapter)
        with patch('os.readlink', return_value=r'C:\Development\_tools\php85\php.exe'):
            rows, queues = app.workers()
        self.assertEqual(rows['fixture:1']['state'], 'RUNNING')
        self.assertEqual(queues, {'fixture-redis': ['backfill', 'main']})
        self.assertEqual(app._redis_framework_connections['default']['database'], 4)
        app.validate_queue_connections()
        self.assertEqual(app.counts(), {'jobs': 8, 'reserved': 2})
        self.assertEqual(app._redis_last_count_proof, {
            'framework_connection_identity_match': True,
            'payloads_read': False, 'data_write_commands': 0,
        })
        self.assertNotIn('synthetic-test-only', b''.join(arg[1] or b'' for arg in app.calls).decode())
        self.assertFalse(any('AppKernel' in str(arg) or 'bootstrap/app.php' in str(arg)
                             for call in app.calls for arg in call[0]))

    def test_cached_config_drift_refuses_before_counts(self):
        app = FakeRelease(self.root, self.cache, self.config)
        app.bind_native_redis_adapter(self.adapter)
        with patch('os.readlink', return_value=r'C:\Development\_tools\php85\php.exe'):
            app.workers()
        self.cache.write_text('synthetic drift', encoding='ascii')
        with self.assertRaisesRegex(RuntimeError, '^cached_config_drift$'):
            app.counts()

    def test_nonempty_redis_url_refuses_without_emitting_url(self):
        config = json.loads(json.dumps(self.config))
        config['database']['redis']['default']['url'] = 'redis://fake-user:fake-pass@invalid.example'
        app = FakeRelease(self.root, self.cache, config)
        app.bind_native_redis_adapter(self.adapter)
        with patch('os.readlink', return_value=r'C:\Development\_tools\php85\php.exe'):
            with self.assertRaisesRegex(RuntimeError, '^unsupported_cached_redis_url$'):
                app.workers()
        self.assertNotIn('fake-pass', str(app.calls))

    def test_unpinned_adapter_source_refuses(self):
        app = FakeRelease(self.root, self.cache, self.config)
        with self.assertRaisesRegex(RuntimeError, '^native_adapter_source_drift$'):
            app.bind_native_redis_adapter(self.adapter + '\n')


if __name__ == '__main__':
    unittest.main()
