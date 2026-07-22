import subprocess
import tempfile
import unittest
from pathlib import Path

from iot_ca.engine import StepCAEngine, StepCAError


class EngineTests(unittest.TestCase):
    def test_command_errors_do_not_expose_ansi_formatting(self):
        def failing_runner(command, *, env, timeout):
            raise subprocess.CalledProcessError(
                1,
                command,
                stderr="\x1b[32m\u2714\x1b[0m CA: forbidden",
            )

        with tempfile.TemporaryDirectory() as temporary:
            engine = StepCAEngine(temporary, command_runner=failing_runner)
            with self.assertRaisesRegex(StepCAError, r"Smallstep command failed: \u2714 CA: forbidden") as error:
                engine._execute(["step", "ca"], env={})
            self.assertNotIn("\x1b", str(error.exception))

    def test_provisioner_policy_allows_profile_maximum(self):
        commands = []

        def recording_runner(command, *, env, timeout):
            commands.append((command, env))
            return ""

        with tempfile.TemporaryDirectory() as temporary:
            engine = StepCAEngine(Path(temporary), command_runner=recording_runner)
            engine.apply_provisioner_policy()

        self.assertEqual(len(commands), 2)
        self.assertEqual([item[0][4] for item in commands], ["iot-ca-admin", "acme"])
        for command, environment in commands:
            self.assertIn("--x509-max-dur=19800h", command)
            self.assertEqual(environment["NO_COLOR"], "1")

    def test_restart_does_not_reapply_offline_policy_through_admin_api(self):
        run_script = (
            Path(__file__).parents[1]
            / "iot_certificate_authority"
            / "rootfs"
            / "run.sh"
        ).read_text()

        self.assertIn('exec step-ca "${CA_CONFIG}"', run_script)
        self.assertNotIn("apply_provisioner_policy()", run_script)


if __name__ == "__main__":
    unittest.main()
