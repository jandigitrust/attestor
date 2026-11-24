"""The isolated acceptance runner consumes an operator-managed Attestor."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from integration import stage_demo


class StageDemoTests(unittest.TestCase):
    def test_external_attestor_must_be_a_loopback_origin(self):
        with tempfile.TemporaryDirectory() as directory:
            for filename in ("certificate.pem", "private_key.pem"):
                (Path(directory) / filename).touch()
            for url in (
                "https://127.0.0.1:18001",
                "http://example.test:18001",
                "http://127.0.0.1:18001/other",
                "http://127.0.0.1",
            ):
                with self.subTest(url=url), self.assertRaises(ValueError):
                    stage_demo.check_attestor(url, Path(directory))

    def test_stage_uses_a_ready_attestor_without_starting_it(self):
        with tempfile.TemporaryDirectory() as directory:
            certificates = Path(directory)
            for filename in ("certificate.pem", "private_key.pem"):
                (certificates / filename).touch()
            with patch.object(stage_demo.http.client, "HTTPConnection") as client:
                client.return_value.getresponse.return_value = Mock(status=204)
                url = stage_demo.check_attestor(
                    "http://127.0.0.1:18001/", certificates
                )
            self.assertEqual(url, "http://127.0.0.1:18001")
            client.return_value.request.assert_called_once_with("HEAD", "/tee-report")
            client.return_value.close.assert_called_once()
            config = stage_demo.nginx_config(Path(directory), certificates, url)
            self.assertIn("proxy_pass http://127.0.0.1:18001/tee-report;", config)


if __name__ == "__main__":
    unittest.main()
