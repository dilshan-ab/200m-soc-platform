"""Exercise deployment recovery without touching a Docker daemon."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / 'deploy' / 'restart-services.sh'
DOCKER = '''#!/usr/bin/env python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ['FAKE_DOCKER_DIR'])
args = sys.argv[1:]
with (root / 'calls').open('a') as out:
    out.write(json.dumps(args) + '\\n')
mode = os.environ['FAKE_DOCKER_MODE']
if args[1] == 'pull' and mode == 'pull-failure':
    sys.exit(7)
if args[1] == 'rm' and mode == 'cleanup-failure':
    sys.exit(8)
if args[1] == 'up':
    count = root / 'attempts'
    attempt = int(count.read_text()) + 1 if count.exists() else 1
    count.write_text(str(attempt))
    if mode == 'unrelated-failure':
        print('Error: database health check failed', file=sys.stderr)
        sys.exit(9)
    if mode == 'foreign-conflict':
        print('Conflict. The container name "/another-project-web-1" is already in use', file=sys.stderr)
        sys.exit(10)
    if mode != 'success' and attempt == 1:
        print('Error response from daemon: Conflict. The container name "/9c26fa8a26e5_soc-web-1" is already in use', file=sys.stderr)
        sys.exit(1)
    if mode == 'retry-failure':
        sys.exit(11)
'''


class RestartServicesTest(unittest.TestCase):
    def run_deploy(self, mode):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docker = root / 'docker'
            docker.write_text(DOCKER)
            docker.chmod(0o755)
            result = subprocess.run(
                ['bash', str(SCRIPT)], cwd=root, capture_output=True, text=True,
                env={**os.environ, 'PATH': f'{root}:{os.environ["PATH"]}',
                     'FAKE_DOCKER_DIR': directory, 'FAKE_DOCKER_MODE': mode},
                timeout=10,
            )
            import json
            calls = [json.loads(line) for line in (root / 'calls').read_text().splitlines()]
        return result.returncode, calls

    def test_success_never_removes_containers(self):
        code, calls = self.run_deploy('success')
        self.assertEqual(code, 0)
        self.assertEqual([call[1] for call in calls], ['pull', 'up'])

    def test_name_conflict_recreates_only_application_services_once(self):
        code, calls = self.run_deploy('conflict')
        self.assertEqual(code, 0)
        self.assertEqual([call[1] for call in calls], ['pull', 'up', 'rm', 'up'])
        self.assertEqual(calls[2], ['compose', 'rm', '--stop', '--force', 'backend', 'web'])

    def test_unrelated_failure_is_not_retried(self):
        code, calls = self.run_deploy('unrelated-failure')
        self.assertEqual(code, 9)
        self.assertEqual([call[1] for call in calls], ['pull', 'up'])

    def test_other_project_conflict_is_not_cleaned_up(self):
        code, calls = self.run_deploy('foreign-conflict')
        self.assertEqual(code, 10)
        self.assertEqual([call[1] for call in calls], ['pull', 'up'])

    def test_pull_failure_never_stops_existing_services(self):
        code, calls = self.run_deploy('pull-failure')
        self.assertEqual(code, 7)
        self.assertEqual([call[1] for call in calls], ['pull'])

    def test_cleanup_failure_stops_recovery(self):
        code, calls = self.run_deploy('cleanup-failure')
        self.assertEqual(code, 8)
        self.assertEqual([call[1] for call in calls], ['pull', 'up', 'rm'])

    def test_retry_failure_is_reported_without_looping(self):
        code, calls = self.run_deploy('retry-failure')
        self.assertEqual(code, 11)
        self.assertEqual([call[1] for call in calls], ['pull', 'up', 'rm', 'up'])


if __name__ == '__main__':
    unittest.main()
