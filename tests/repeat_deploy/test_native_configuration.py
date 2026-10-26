import hashlib
import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE = ROOT / 'roles/RepeatDeploy/files/native_configuration.py'
spec = importlib.util.spec_from_file_location('native_configuration', MODULE)
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
PHP = pathlib.Path(r'C:\Development\_tools\php85\php.exe')


def tagged_bool(value):
    return hashlib.sha256(json.dumps({'type': 'bool', 'value': value}, separators=(',', ':')).encode()).hexdigest()


class LocalPhpController:
    def __init__(self, php):
        self.p = {'php_cli': str(php)}

    def run(self, argv, *, input=None, **kwargs):
        if argv[0] != 'unshare' or argv[1] != '--net':
            raise AssertionError('native config proof must use its isolated PHP invocation')
        try:
            result = subprocess.run([self.p['php_cli'], *argv[3:]], input=input,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except subprocess.CalledProcessError as error:
            raise native.ConfigurationRefuse('synthetic_php_command_refused') from error
        if result.stdout[:1] != b'{':
            raise AssertionError('PHP proof returned a non-JSON result: ' + repr(result.stdout[:80]))
        if result.stderr:
            raise AssertionError('PHP proof emitted diagnostics: ' + result.stderr.decode(errors='replace'))
        return result.stdout


class NativeConfigurationTests(unittest.TestCase):
    def setUp(self):
        if not PHP.is_file():
            self.skipTest('shared PHP 8.5 runtime is unavailable')
        self.tmp = tempfile.TemporaryDirectory(prefix='native-config-fixture-')
        self.root = pathlib.Path(self.tmp.name)
        self.old = self.root / 'old.php'
        self.new = self.root / 'new.php'
        self.controller = LocalPhpController(PHP)
        self.old_config = {
            'app': {'name': 'fixture', 'reporting': {'enabled': False}},
            'queue': {'default': 'database', 'after_commit': True},
            'cache': {'default': 'file'},
        }
        self.new_config = {
            'app': {'name': 'fixture', 'reporting': {'enabled': True}},
            'queue': {'default': 'redis', 'after_commit': False},
            'cache': {'default': 'redis'},
        }
        self.allowed = {'app.reporting.enabled': {
            'old': tagged_bool(False), 'new': tagged_bool(True),
        }}
        self.write_config(self.old, self.old_config)
        self.write_config(self.new, self.new_config)

    def tearDown(self):
        target = pathlib.Path(self.tmp.name).resolve()
        self.assertEqual(target.parent, pathlib.Path(tempfile.gettempdir()).resolve())
        self.assertTrue(target.name.startswith('native-config-fixture-'))
        self.tmp.cleanup()

    @staticmethod
    def write_config(path, value):
        # These fixtures use only arrays and scalar booleans/strings, so JSON is
        # a safe source for PHP's native array parser after decoding.
        encoded = json.dumps(value, ensure_ascii=False)
        php_string = json.dumps(encoded)
        source = "<?php\nreturn json_decode(" + php_string + ", true, 512, JSON_THROW_ON_ERROR);\n"
        path.write_text(source, encoding='utf-8')

    def read_config(self, path):
        code = '$c=require $argv[1];echo json_encode($c,JSON_THROW_ON_ERROR);'
        result = subprocess.run([str(PHP), '-r', code, str(path)], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=True)
        return json.loads(result.stdout)

    def test_merges_only_approved_node_and_proves_all_other_old_values_preserved(self):
        proof = native.merge_native_config_nodes(self.controller, self.old, self.new, self.allowed)
        self.assertEqual(proof['approved_native_nodes_applied'], 1)
        self.assertTrue(proof['unrelated_old_configuration_preserved'])
        self.assertTrue(native.native_config_proof(self.controller, self.old, self.new, self.allowed))
        self.assertEqual(self.read_config(self.new), {
            **self.old_config,
            'app': {'name': 'fixture', 'reporting': {'enabled': True}},
        })

    def test_old_node_hash_mismatch_refuses_before_replacing_candidate_cache(self):
        before = self.new.read_bytes()
        wrong = {'app.reporting.enabled': {'old': '0' * 64, 'new': tagged_bool(True)}}
        with self.assertRaises(native.ConfigurationRefuse):
            native.merge_native_config_nodes(self.controller, self.old, self.new, wrong)
        self.assertEqual(self.new.read_bytes(), before)

    def test_unknown_configuration_change_fails_typed_proof(self):
        wrong = {'app.reporting.enabled': self.allowed['app.reporting.enabled']}
        self.assertFalse(native.native_config_proof(self.controller, self.old, self.new, wrong))

    def test_private_bootstrap_without_deltas_requires_full_native_equality(self):
        self.assertFalse(native.native_config_proof(self.controller, self.old, self.new, {}))
        self.write_config(self.new, self.old_config)
        self.assertTrue(native.native_config_proof(self.controller, self.old, self.new, {}))


if __name__ == '__main__':
    unittest.main()
