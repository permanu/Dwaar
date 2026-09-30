"""Verify CI coverage and fail-fast behavior without compiling Rust."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'ci-rust.sh'


class RustCITest(unittest.TestCase):
    def run_ci(self, fail=''):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cargo = root / 'cargo'
            cargo.write_text('#!/bin/sh\necho "$*" >> "$CI_COMMAND_LOG"\n'
                             '[ "$*" != "$CI_FAIL_COMMAND" ]\n')
            cargo.chmod(0o755)
            log = root / 'commands'
            env = dict(os.environ, PATH=f'{root}:{os.environ["PATH"]}',
                       CI_COMMAND_LOG=str(log), CI_FAIL_COMMAND=fail)
            result = subprocess.run(['sh', str(SCRIPT)], env=env, capture_output=True)
            return result.returncode, log.read_text().splitlines() if log.exists() else []

    def test_complete_coverage(self):
        code, calls = self.run_ci()
        self.assertEqual(code, 0)
        self.assertEqual(calls, [
            'fmt --all --check',
            'clippy --locked --workspace --all-targets --all-features -- -D warnings',
            'test --locked --workspace --exclude dwaar-cli',
            'test --locked -p dwaar-cli --bins --test cli_integration --test admin_route_state --test multi_upstream --test route_path --test webhook_route',
            'test --locked --workspace --exclude dwaar-cli -- --ignored --nocapture',
            'check --locked --workspace --release',
        ])

    def test_each_failure_stops_remaining_work(self):
        _, calls = self.run_ci()
        self.assertTrue(calls)
        for index, call in enumerate(calls):
            with self.subTest(command=call):
                code, actual = self.run_ci(call)
                self.assertNotEqual(code, 0)
                self.assertEqual(actual, calls[:index + 1])


if __name__ == '__main__':
    unittest.main()
