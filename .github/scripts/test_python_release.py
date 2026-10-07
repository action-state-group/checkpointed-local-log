# SPDX-License-Identifier: Apache-2.0
import unittest
from check_python_release import validate


class ReleaseGate(unittest.TestCase):
    def test_matching_python_release(self):
        validate("python/v0.5.0", 'version = "0.5.0"\n')

    def test_other_domains_and_malformed_or_wrong_versions(self):
        for tag in ["ts/v0.5.0", "go/v0.5.0", "crates/checkpointed-local-log-v0.5.0", "v0.5.0", "python/v0.5.1", "python/v00.5.0", "python/v0.5.0/extra", "python/v0.5.0rc1", "unrelated"]:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                validate(tag, 'version = "0.5.0"\n')


if __name__ == "__main__":
    unittest.main()
