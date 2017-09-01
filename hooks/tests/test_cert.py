import os
import shutil
import tempfile

from testtools import TestCase
from mock import patch

import hooks


original_open = open


def _unit_get(value):
    return value


def _unit_get_public_address_changed(value):
    if value == "public-address":
        return "changed"
    return "foo"


def _unit_get_private_address_changed(value):
    if value == "private-address":
        return "changed"
    return "foo"


class CertTests(TestCase):
    def setUp(self):
        super(CertTests, self).setUp()
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
        super(CertTests, self).tearDown()
        shutil.rmtree(self.tempdir, ignore_errors=True)

    def test_is_selfsigned_cert_stale_missing_key(self):
        """Missing cert, we should regenerate."""
        config = {"servername": "servername"}
        cert_file = os.path.join(self.tempdir, "cert")
        key_file = os.path.join(self.tempdir, "key")
        with open(cert_file, "w") as f:
            f.write("foo")
        self.assertTrue(
            hooks.is_selfsigned_cert_stale(config, cert_file, key_file))

    def test_is_selfsigned_cert_stale_missing_cert(self):
        """Missing cert, we should regenerate."""
        config = {"servername": "servername"}
        cert_file = os.path.join(self.tempdir, "cert")
        key_file = os.path.join(self.tempdir, "key")
        with open(key_file, "w") as f:
            f.write("foo")
        self.assertTrue(
            hooks.is_selfsigned_cert_stale(config, cert_file, key_file))

    @patch("hooks.log")
    @patch("hooks.unit_get", return_value="unit")
    def test_is_selfsigned_cert_stale_cn_changed(self, unit_get, log):
        """With different servername, cert *should* be regenerated."""
        config = {"servername": "servername"}
        cert_file = os.path.join(self.tempdir, "cert")
        key_file = os.path.join(self.tempdir, "key")
        hooks.gen_selfsigned_cert(config, cert_file, key_file)
        config["servername"] = "changed"
        self.assertTrue(
            hooks.is_selfsigned_cert_stale(config, cert_file, key_file))

    @patch("hooks.log")
    @patch("hooks.unit_get", side_effect=_unit_get)
    def test_is_selfsigned_cert_stale_public_address_changed(
            self, unit_get, log):
        """With different servername, cert *should* be regenerated."""
        try:
            from pyasn1.codec.der import decoder  # noqa
            from pyasn1_modules import rfc2459  # noqa
        except ImportError:
            # This test is utopic+ only
            return
        config = {"servername": "servername"}
        cert_file = os.path.join(self.tempdir, "cert")
        key_file = os.path.join(self.tempdir, "key")
        hooks.gen_selfsigned_cert(config, cert_file, key_file)
        unit_get.side_effect = _unit_get_public_address_changed
        self.assertTrue(
            hooks.is_selfsigned_cert_stale(config, cert_file, key_file))

    @patch("hooks.log")
    @patch("hooks.unit_get", side_effect=_unit_get)
    def test_is_selfsigned_cert_stale_private_address_changed(
            self, unit_get, log):
        """With different servername, cert *should* be regenerated."""
        try:
            from pyasn1.codec.der import decoder  # noqa
            from pyasn1_modules import rfc2459  # noqa
        except ImportError:
            # This test is utopic+ only
            return
        config = {"servername": "servername"}
        cert_file = os.path.join(self.tempdir, "cert")
        key_file = os.path.join(self.tempdir, "key")
        hooks.gen_selfsigned_cert(config, cert_file, key_file)
        unit_get.side_effect = _unit_get_private_address_changed
        self.assertTrue(
            hooks.is_selfsigned_cert_stale(config, cert_file, key_file))

    @patch("hooks.log")
    @patch("hooks.unit_get", return_value="unit")
    def test_is_selfsigned_cert_stale_assert_false(self, unit_get, log):
        """Happy path, cert exists, doesn't need to be regenerated."""
        config = {"servername": "servername"}
        cert_file = os.path.join(self.tempdir, "cert")
        key_file = os.path.join(self.tempdir, "key")
        hooks.gen_selfsigned_cert(config, cert_file, key_file)
        self.assertFalse(
            hooks.is_selfsigned_cert_stale(config, cert_file, key_file))

    @patch("hooks.log")
    @patch("hooks.unit_get", return_value="unit")
    def test_gen_selfsigned_cert(self, unit_get, log):
        """
        Happy path, make sure we can generate a cert, invalidate,
        and write another.
        """
        config = {"servername": "servername"}
        cert_file = os.path.join(self.tempdir, "cert")
        key_file = os.path.join(self.tempdir, "key")
        hooks.gen_selfsigned_cert(config, cert_file, key_file)
        config["servername"] = "changed"
        self.assertTrue(
            hooks.is_selfsigned_cert_stale(config, cert_file, key_file))
        hooks.gen_selfsigned_cert(config, cert_file, key_file)
        self.assertFalse(
            hooks.is_selfsigned_cert_stale(config, cert_file, key_file))
