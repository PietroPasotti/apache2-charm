from contextlib import contextmanager
import os.path
from tempfile import mkdtemp
from shutil import rmtree

from testtools import TestCase
from mock import (
    call,
    patch,
)
import yaml

import hooks


@contextmanager
def temp_dir():
    directory = mkdtemp()
    try:
        yield directory
    finally:
        rmtree(directory)


class HooksTest(TestCase):
    def test__get_key_file_location_empty(self):
        """No ssl_keylocation, expect None."""
        self.assertEqual(hooks._get_key_file_location(
            {"ssl_keylocation": None}), None)

    def test__get_key_file_location(self):
        """ssl_keylocation, expect correct path."""
        self.assertEqual(hooks._get_key_file_location(
            {"ssl_keylocation": "foo"}), "/etc/ssl/private/foo")

    def test__get_cert_file_location_empty(self):
        """No ssl_keylocation, expect None."""
        self.assertEqual(hooks._get_cert_file_location(
            {"ssl_certlocation": None}), None)

    def test__get_cert_file_location(self):
        """ssl_keylocation, expect correct path."""
        self.assertEqual(hooks._get_cert_file_location(
            {"ssl_certlocation": "foo"}), "/etc/ssl/certs/foo")

    def test__get_chain_file_location_empty(self):
        """No ssl_keylocation, expect None."""
        self.assertEqual(hooks._get_chain_file_location(
            {"ssl_chainlocation": None}), None)

    def test__get_chain_file_location(self):
        """ssl_keylocation, expect correct path."""
        self.assertEqual(hooks._get_chain_file_location(
            {"ssl_chainlocation": "foo"}), "/etc/ssl/certs/foo")


class TestApacheWebsites(TestCase):

    def test_from_config_empty(self):
        relations = [{
            '__relid__': 'idrel',
        }]
        websites = hooks.ApacheWebsites.from_config(relations, [])
        self.assertEqual(websites.relations, {'idrel': {
            'domain': None,
            'enabled': False,
            'ports': [],
            'site_config': None,
            'site_modules': [],
            }})

    def test_from_config_filled(self):
        relations = [{
            '__relid__': 'idrel',
            'domain': 'foo.example.com',
            'ports': '80 8080',
            'site_config': 'configfoo',
            'site_modules': 'foo bar',
        }]
        websites = hooks.ApacheWebsites.from_config(relations, [])
        self.assertEqual(websites.relations, {'idrel': {
            'domain': 'foo.example.com',
            'enabled': False,
            'ports': [80, 8080],
            'site_config': 'configfoo',
            'site_modules': ['foo', 'bar'],
            }})

    def test_from_config_disabled_module_disables_site(self):
        relations = [{
            '__relid__': 'idrel',
            'site_modules': 'foo bar',
            'enabled': 'true',
        }]
        with patch('hooks.log') as log_mock:
            websites = hooks.ApacheWebsites.from_config(relations, ['foo'])
        self.assertEqual(websites.relations['idrel']['enabled'], False)
        log_mock.assert_called_once_with(
            'site idrel requires disabled_module foo')

    def test_write_configs(self):
        with temp_dir() as configs_temp:

            def site_filename(name):
                return os.path.join(configs_temp, name)

            websites = hooks.ApacheWebsites({
                'cfg': {'site_config': 'foobar'},
                'fcg': {'site_config': None},
                })
            open(site_filename('fcg'), 'w').write('')
            self.assertTrue(os.path.exists(site_filename('fcg')))
            with patch('hooks.site_filename', site_filename):
                websites.write_configs()
            self.assertEqual('foobar', open(site_filename('cfg')).read())
            self.assertFalse(os.path.exists(site_filename('fcg')))

    def test_iter_enabled_sites(self):
        websites = hooks.ApacheWebsites({
            'fcg': {'site_config': None, 'enabled': True},
            'cgf': {'site_config': None, 'enabled': False},
            })
        self.assertItemsEqual(
            websites.iter_enabled_sites(),
            [('fcg', {'site_config': None, 'enabled': True})])

    def test_enable_sites(self):
        websites = hooks.ApacheWebsites({
            'fcg': {'site_config': None, 'enabled': False},
            'cgf': {'site_config': None, 'enabled': False},
            })
        with patch('subprocess.check_call') as cc_mock:
            websites.enable_sites()
        self.assertEqual(len(cc_mock.mock_calls), 0)
        websites.relations['fcg']['enabled'] = True
        with patch('subprocess.check_call') as cc_mock:
            websites.enable_sites()
        cc_mock.assert_called_once_with(['/usr/sbin/a2ensite', 'fcg'])
        websites.relations['cgf']['enabled'] = True
        with patch('subprocess.check_call') as cc_mock:
            websites.enable_sites()
        cc_mock.assert_called_once_with(['/usr/sbin/a2ensite', 'cgf', 'fcg'])

    def test_disable_sites(self):
        websites = hooks.ApacheWebsites({
            'fcg': {'site_config': None, 'enabled': True},
            'cgf': {'site_config': None, 'enabled': True},
            })
        with temp_dir() as conf_dir:

            def site_filename(f, e=False):
                return os.path.join(conf_dir, f)

            with patch('hooks.site_filename', site_filename):
                open(hooks.site_filename('fcg'), 'w').close()
                open(hooks.site_filename('cgf'), 'w').close()
                with patch('subprocess.check_output') as co_mock:
                    websites.disable_sites()
                self.assertEqual(len(co_mock.mock_calls), 0)
                websites.relations['fcg']['enabled'] = False
                with patch('subprocess.check_output') as co_mock:
                    websites.disable_sites()
                co_mock.assert_called_once_with(['/usr/sbin/a2dissite', 'fcg'])
                websites.relations['cgf']['enabled'] = False
                with patch('subprocess.check_output') as co_mock:
                    websites.disable_sites()
        co_mock.assert_called_once_with(['/usr/sbin/a2dissite', 'cgf', 'fcg'])

    def test_list_enabled_modules(self):
        websites = hooks.ApacheWebsites({
            'fcg': {'site_modules': ['foo'], 'enabled': True},
            'cgf': {'site_modules': ['foo', 'bar'], 'enabled': True},
            'gcf': {'site_modules': ['foo', 'baz'], 'enabled': False},
            })
        self.assertEqual(
            websites.list_enabled_modules(['qux']), set(['foo', 'bar', 'qux']))

    def test_list_enabled_ports(self):
        websites = hooks.ApacheWebsites({
            'fcg': {'ports': [80], 'enabled': True},
            'cgf': {'ports': [80, 81], 'enabled': True},
            'gcf': {'ports': [81, 82], 'enabled': False},
            })
        self.assertEqual(
            websites.list_enabled_ports(), set([80, 81]))

    def test_configure_extra_ports(self):
        websites = hooks.ApacheWebsites({
            'fcg': {'ports': [80], 'enabled': True},
            'cgf': {'ports': [80, 81], 'enabled': True},
            'gcf': {'ports': [81, 82], 'enabled': False},
            })
        with patch('hooks.conf_enable') as ce_mock:
            with temp_dir() as conf_dir:
                fake_conf = os.path.join(conf_dir, 'extra_ports.conf')
                with patch('hooks.conf_filename', return_value=fake_conf):
                    with patch('hooks.open_port'):
                        websites.configure_extra_ports()
        ce_mock.assert_called_once_with('extra_ports')


class TestEnsurePorts(TestCase):

    def test_ensure_ports(self):
        with patch('hooks.open_port') as hop_mock:
            with patch('hooks.set_open_ports') as hsop_mock:
                with patch('hooks.get_open_ports', return_value=[]):
                    hooks.ensure_ports([80, 81])
        self.assertEqual(hop_mock.mock_calls, [call(80), call(81)])
        hsop_mock.assert_called_once_with([80, 81])

    def test_idempotent(self):
        with patch('hooks.get_open_ports', return_value=[81, 82]):
            with patch('hooks.open_port') as hop_mock:
                with patch('hooks.set_open_ports') as hsop_mock:
                    hooks.ensure_ports([81, 83, 82])
        self.assertEqual(hop_mock.mock_calls, [call(83)])
        hsop_mock.assert_called_once_with([81, 82, 83])

    def test_closes_unneeded(self):
        with patch('hooks.get_open_ports', return_value=[81, 82, 83, 84]):
            with patch('hooks.close_port') as hcp_mock:
                with patch('hooks.set_open_ports') as hsop_mock:
                    hooks.ensure_ports([81, 82])
        self.assertEqual(hcp_mock.mock_calls, [call(83), call(84)])
        hsop_mock.assert_called_once_with([81, 82])


class TestGetSetOpenPorts(TestCase):

    def test_get_open_ports(self):
        with temp_dir() as charm_dir:
            with patch('os.environ', {'CHARM_DIR': charm_dir}):
                self.assertEqual(hooks.get_open_ports(), [])
                with open(os.path.join(charm_dir, 'ports.yaml'), 'w') as pfile:
                    yaml.safe_dump([47, 67], pfile)
                self.assertEqual(hooks.get_open_ports(), [47, 67])

    def test_set_open_ports(self):
        with temp_dir() as charm_dir:
            with patch('os.environ', {'CHARM_DIR': charm_dir}):
                hooks.set_open_ports([44, 23])
            with open(os.path.join(charm_dir, 'ports.yaml')) as pfile:
                self.assertEqual(yaml.safe_load(pfile), [44, 23])
