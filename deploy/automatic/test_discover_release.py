import json
from pathlib import Path
import tempfile
import unittest

import discover_release as d


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / ".upstream-sync.json").write_text(json.dumps({"repository": d.UPSTREAM, "major": 2,
            "current_tag": "v2.9.3", "current_commit": "a" * 40}))
        self.releases = [self.release("v2.9.4"), self.release("v3.0.0")]
        self.existing = None
        self.queries = []

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def release(tag):
        return {"tag_name": tag, "draft": False, "prerelease": False, "published_at": "2026-10-25"}

    def fetch(self, path):
        self.queries.append(path)
        return self.releases if path.startswith("/repos/" + d.UPSTREAM) else self.existing

    def refs(self, repo, refs):
        if repo == d.UPSTREAM:
            return {refs[0]: "b" * 40, refs[1]: "c" * 40}
        return {refs[0]: "d" * 40}

    def test_pins_peeled_stable_identity_and_preserves_release_parent(self):
        result = d.discover(self.root, self.fetch, self.refs)
        self.assertTrue(result["available"])
        self.assertEqual(result["upstream_commit"], "c" * 40)
        self.assertEqual(result["release_parent"], "d" * 40)
        self.assertEqual(result["major_available"], "v3.0.0")

    def test_prereleases_drafts_downgrades_and_shell_tags_are_ignored(self):
        self.releases = [self.release(x) for x in ("v2.9.3", "v2.9.2", "v2.9.4;bad", "v2.9.4-rc.1", "v3.0.0")]
        self.releases += [dict(self.release("v2.9.9"), draft=True), dict(self.release("v2.9.8"), prerelease=True)]
        self.assertFalse(d.discover(self.root, self.fetch, self.refs)["available"])

    def test_existing_release_prevents_duplicate_publication_without_claiming_provenance(self):
        self.existing = dict(self.release("rival-auto-v2.9.4"), assets=[{"name": n} for n in ("release.json", "release.sigstore.jsonl", "source.bundle")])
        result = d.discover(self.root, self.fetch, self.refs)
        self.assertFalse(result["available"])
        self.assertIn("verifies-independently", result["reason"])

    def test_partial_release_is_a_stop_not_a_retry(self):
        self.existing = dict(self.release("rival-auto-v2.9.4"), draft=True)
        with self.assertRaisesRegex(ValueError, "requires review"):
            d.discover(self.root, self.fetch, self.refs)

    def test_missing_tag_stops(self):
        with self.assertRaisesRegex(ValueError, "pinned Git identity"):
            d.discover(self.root, self.fetch, lambda *_: {})

    def test_pagination_limit_stops(self):
        with self.assertRaisesRegex(ValueError, "pagination"):
            d.discover(self.root, lambda _: [self.release("v2.9.4")] * 100, self.refs)

    def test_policy_cannot_switch_upstream_or_major(self):
        for field, value in (("repository", "someone/else"), ("major", 3), ("major", True)):
            config = json.loads((self.root / ".upstream-sync.json").read_text())
            config[field] = value
            (self.root / ".upstream-sync.json").write_text(json.dumps(config))
            with self.assertRaises(ValueError):
                d.discover(self.root, self.fetch, self.refs)


if __name__ == "__main__":
    unittest.main()
