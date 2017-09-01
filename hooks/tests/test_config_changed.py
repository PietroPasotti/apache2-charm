from testtools import TestCase
import hooks
from mock import patch
import shutil
import tempfile
import os
import sys

sys.path.insert(0, os.path.join(os.environ['CHARM_DIR'], 'lib'))
from charmhelpers.core import hookenv


class ConfigChangedTest(TestCase):
    def setUp(self):
        super(ConfigChangedTest, self).setUp()
        self.dirname = tempfile.mkdtemp()

    def tearDown(self):
        super(ConfigChangedTest, self).tearDown()
        if os.path.exists(self.dirname):
            shutil.rmtree(self.dirname)

    @patch('hooks.get_open_ports')
    @patch('hooks.set_open_ports')
    @patch('hooks.subprocess.call')
    @patch('hooks.close_port')
    @patch('hooks.open_port')
    @patch('hooks.conf_disable')
    @patch('hooks.ensure_extra_packages')
    @patch('hooks.ensure_package_status')
    @patch('hooks.ship_logrotate_conf')
    @patch('hooks.update_nrpe_checks')
    @patch('hooks.run')
    @patch('hooks.create_security')
    @patch('hooks.create_mpm_workerfile')
    @patch('hooks.log')
    @patch('hooks.relation_ids')
    @patch('hooks.relations_of_type')
    @patch('hooks.config_get')
    @patch('hooks.get_reverseproxy_data')
    @patch('hooks.service_apache2')
    @patch('hooks.relation_set')
    @patch('hooks.enable_mpm')
    def test_config_changed_ensure_empty_site_dir(
            self, mock_enable_mpm, mock_relation_set,
            mock_service_apache2, mock_reverseproxy, mock_config_get,
            mock_relations_of_type, mock_relation_ids, mock_log,
            mock_create_mpm_workerfile, mock_create_security, mock_run,
            mock_update_nrpe_checks, mock_ship_logrotate_conf,
            mock_ensure_package_status, mock_ensure_extra_packages,
            mock_conf_disable, mock_open_port, mock_close_port, mock_call,
            mock_set_open_ports, mock_get_open_ports):
        """config-changed hook: Site directories should be empty."""
        mock_config_get.return_value = hookenv.Config({
            "ssl_cert": "",
            "ssl_key": "",
            "package_status": "",
            "enable_modules": "",
            "disable_modules": "",
            "mpm_type": "",
            "ssl_certlocation": "",
            "ssl_keylocation": "",
            "ssl_chainlocation": "",
            "use_rsyslog": "",
            "config_change_command": "",
            "openid_provider": "",
            "servername": "foobar",
            "vhost_http_template": "",
            "vhost_https_template": "",
            "apt-source": "",
        })
        base = patch.object(hooks, 'default_apache_base_dir', self.dirname)
        config22 = patch.object(hooks, 'default_apache22_config_dir',
                                "%s/conf.d" % self.dirname)
        config24 = patch.object(hooks, 'default_apache24_config_dir',
                                "%s/conf-available" % self.dirname)
        with base, config22, config24:
            os.mkdir("%s/sites-enabled" % self.dirname)
            os.mkdir("%s/sites-available" % self.dirname)
            os.mkdir("%s/conf.d" % self.dirname)
            hooks.config_changed()
            self.assertEqual(
                len(os.listdir("%s/%s" % (self.dirname, "sites-enabled"))), 0)
            self.assertEqual(
                len(os.listdir("%s/%s" % (self.dirname, "sites-available"))),
                0)

    @patch('hooks.orig_config_get')
    @patch('hooks.unit_get')
    def test_config_get_works_with_dict_subclass(
            self, mock_unit_get, mock_orig_config_get):
        """config_get() works with Charm Helper's custom dict subclass"""
        class FakeConfig(dict):
            pass

        mock_orig_config_get.return_value = FakeConfig(servername="")
        mock_unit_get.return_value = "foo"
        config = hooks.config_get()
        self.assertEqual(config["servername"], "foo")
