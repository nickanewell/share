import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("policy", Path(__file__).with_name("render_policy.py"))
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class PolicyTests(unittest.TestCase):
    def inventory(self):
        return {
            "docker-ce": "5:29.3.0-1~ubuntu.24.04~noble",
            "docker-ce-cli": "5:29.3.0-1~ubuntu.24.04~noble",
            "containerd.io": "2.2.1-1~ubuntu.24.04~noble",
            "docker-compose-plugin": "5.1.0-1~ubuntu.24.04~noble",
        }

    def test_retains_epoch_and_approved_major(self):
        self.assertEqual(policy.family("docker-ce", self.inventory()["docker-ce"]), "5:29.*")
        self.assertEqual(policy.family("containerd.io", self.inventory()["containerd.io"]), "2.*")

    def test_zero_major_retains_minor(self):
        self.assertEqual(policy.family("docker-buildx-plugin", "0.32.1-1~ubuntu.24.04~noble"), "0.32.*")

    def test_rejects_new_major_and_config_injection(self):
        for version in ["5:30.0.0-1", "29.3", "29.3.0\nPin-Priority: 1001", "29.3.0;reboot", "29.3.0-rc1"]:
            with self.subTest(version=version):
                with self.assertRaises(ValueError):
                    policy.family("docker-ce", version)

    def test_requires_complete_known_inventory(self):
        for inventory in [{}, {"evil": "1.0.0"}, {**self.inventory(), "unrelated": "1.2.3"}]:
            with self.assertRaises(ValueError):
                policy.render(inventory)

    def test_unknown_optional_packages_blocked(self):
        rendered = policy.render(self.inventory())
        preferences = rendered["etc/apt/preferences.d/rival-share-docker.pref"]
        self.assertIn("Pin: version 5:29.*\nPin-Priority: 500", preferences)
        self.assertIn("Pin-Priority: -1", preferences)
        self.assertNotIn("Pin-Priority: 1001", preferences)
        self.assertIn('"^docker-buildx-plugin$";', rendered["etc/apt/apt.conf.d/99rival-share-maintenance"])

    def test_eastern_dst_and_no_out_of_window_catchup(self):
        files = policy.render(self.inventory())
        timer = files["etc/systemd/system/apt-daily-upgrade.timer.d/rival-share.conf"]
        self.assertIn("OnCalendar=Sun *-*-* 03:00:00 America/New_York", timer)
        self.assertIn("Persistent=false", timer)
        self.assertIn("RandomizedDelaySec=0", timer)

    def test_review_output_cannot_replace_existing_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "proposal"
            policy.write_proposal(output, policy.render(self.inventory()))
            self.assertEqual(len(list(output.rglob("*.pref"))), 1)
            with self.assertRaises(FileExistsError):
                policy.write_proposal(output, policy.render(self.inventory()))

    def test_resolved_system_config_paths_rejected(self):
        for path in [Path("/etc"), Path("/etc/rival-share-policy"), Path("/etc").resolve() / "rival-share-policy"]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                policy.review_output(path)
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(policy.review_output(Path(tmp) / "proposal"), Path(tmp).resolve() / "proposal")


if __name__ == "__main__":
    unittest.main()
