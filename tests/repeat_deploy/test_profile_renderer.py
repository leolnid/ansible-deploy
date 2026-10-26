import importlib.util
import pathlib
import unittest

MODULE = pathlib.Path(__file__).resolve().parents[2] / 'scripts/render-repeat-profile.py'
spec = importlib.util.spec_from_file_location('render_repeat_profile', MODULE)
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)


class ProfileRendererTests(unittest.TestCase):
    def setUp(self):
        self.enrollment = {
            'schema_version': 1,
            'inventory_host': '192.0.2.18',
            'inventory_user': 'ansible',
            'ssh_key_env': 'ANSIBLE_SSH_PRIVATE_KEY',
            'profile': {'schema_version': 1, 'project': 'fixture',
                        'live_manifest': {'candidate_commit': 'a' * 40, 'files': {'artisan': 'b' * 64}}},
        }
        self.manifest = {'candidate_commit': 'c' * 40, 'files': {'artisan': 'd' * 64}}
        self.artifact = {'candidate_commit': 'c' * 40, 'source_archive_sha256': 'e' * 64}

    def test_candidate_is_bound_to_the_current_git_artifact_and_reviewed_baseline(self):
        profile, inventory = renderer.render(self.enrollment, self.manifest, self.artifact)
        self.assertEqual(profile['repeat_deploy_profile']['live_manifest'], self.enrollment['profile']['live_manifest'])
        self.assertEqual(profile['repeat_deploy_profile']['candidate_manifest'], self.manifest)
        self.assertEqual(profile['repeat_deploy_profile']['source_archive_sha256'], 'e' * 64)
        self.assertEqual(inventory['all']['hosts']['selected-app'],
                         {'ansible_host': '192.0.2.18', 'ansible_user': 'ansible'})
        self.assertEqual(set(inventory['all']['hosts']), {'selected-app'})

    def test_old_live_manifest_cannot_be_reused_as_the_new_candidate(self):
        stale = dict(self.manifest, candidate_commit='b' * 40)
        with self.assertRaises(ValueError):
            renderer.render(self.enrollment, stale, self.artifact)

    def test_candidate_or_archive_digest_in_enrollment_is_refused(self):
        for key, value in [('candidate_manifest', self.manifest),
                           ('source_archive_sha256', 'e' * 64)]:
            enrollment = dict(self.enrollment)
            enrollment['profile'] = dict(self.enrollment['profile'], **{key: value})
            with self.assertRaises(ValueError):
                renderer.render(enrollment, self.manifest, self.artifact)

    def test_invalid_artifact_identity_is_refused(self):
        for artifact in [dict(self.artifact, candidate_commit='not-a-commit'),
                         dict(self.artifact, source_archive_sha256='x' * 64)]:
            with self.assertRaises(ValueError):
                renderer.render(self.enrollment, self.manifest, artifact)

    def test_existing_ssh_user_variable_is_validated_and_resolved_without_copying_key(self):
        enrollment = dict(self.enrollment)
        enrollment.pop('inventory_user')
        enrollment['inventory_user_env'] = 'SSH_USER'
        _, inventory = renderer.render(enrollment, self.manifest, self.artifact,
                                       {'SSH_USER': 'legacy-deployer', 'SSH_PRIVATE_KEY': 'synthetic-private-key'})
        host = inventory['all']['hosts']['selected-app']
        self.assertEqual(host['ansible_user'], 'legacy-deployer')
        self.assertNotIn('synthetic-private-key', json_text(inventory))

    def test_user_and_key_variable_names_are_not_open_ended(self):
        enrollment = dict(self.enrollment, ssh_key_env='UNRELATED_SECRET')
        with self.assertRaises(ValueError):
            renderer.render(enrollment, self.manifest, self.artifact)
        enrollment = dict(self.enrollment)
        enrollment.pop('inventory_user')
        enrollment['inventory_user_env'] = 'UNRELATED_SECRET'
        with self.assertRaises(ValueError):
            renderer.render(enrollment, self.manifest, self.artifact, {'UNRELATED_SECRET': 'tester'})


def json_text(value):
    import json
    return json.dumps(value)


if __name__ == '__main__':
    unittest.main()
