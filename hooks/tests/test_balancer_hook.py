from pprint import pformat
import os
import shutil
import tempfile
import yaml

from testtools import TestCase
from mock import patch, call, MagicMock

import hooks


FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')


original_open = open


class BalancerRelationTest(TestCase):

    def setUp(self):
        super(BalancerRelationTest, self).setUp()

        self.relations_of_type = self.patch_hook("relations_of_type")
        self.config_get = self.patch_hook("config_get")
        self.log = self.patch_hook("log")
        self.write_balancer_config = self.patch_hook("write_balancer_config")

    def patch_hook(self, hook_name):
        mock_controller = patch.object(hooks, hook_name)
        mock = mock_controller.start()
        self.addCleanup(mock_controller.stop)
        return mock

    def test_relation_data_returns_no_relations(self):
        self.relations_of_type.return_value = []
        self.assertIs(None, hooks.update_balancers())
        self.log.assert_called_once_with("No relation data, exiting.")
        self.write_balancer_config.assert_not_called()

    def test_no_port_in_relation_data(self):
        self.relations_of_type.return_value = [
            {"private-address": "1.2.3.4",
             "__unit__": "foo/1"},
        ]
        self.assertIs(None, hooks.update_balancers())
        self.log.assert_called_once_with(
            "No port in relation data for 'foo/1', skipping.")
        self.write_balancer_config.assert_not_called()

    def test_no_private_address_in_relation_data(self):
        self.relations_of_type.return_value = [
            {"port": 4242,
             "__unit__": "foo/1"},
        ]
        self.assertIs(None, hooks.update_balancers())
        self.log.assert_called_once_with(
            "No private-address in relation data for 'foo/1', skipping.")
        self.write_balancer_config.assert_not_called()

    def test_sitenames_in_relation_data(self):
        self.relations_of_type.return_value = [
            {"private-address": "1.2.3.4",
             "port": 4242,
             "sitenames": "foo.internal bar.internal",
             "__unit__": "foo/1"},
            ]
        expected = {
            "foo.internal": ["1.2.3.4:4242"],
            "bar.internal": ["1.2.3.4:4242"],
        }
        self.assertEqual(hooks.update_balancers(), expected)
        self.write_balancer_config.assert_called_once_with(expected)

    def test_all_services_in_relation_data(self):
        self.relations_of_type.return_value = [
            {"private-address": "1.2.3.4",
             "port": 80,
             "__unit__": "foo/1",
             "all_services": yaml.dump(
                 [
                     {"service_name": "foo.internal",
                      "service_port": 4242},
                     {"service_name": "bar.internal",
                      "service_port": 4243},
                     ]
                 ),
             },
        ]
        expected = {
            "foo.internal": ["1.2.3.4:4242"],
            "bar.internal": ["1.2.3.4:4243"],
        }
        self.assertEqual(hooks.update_balancers(), expected)
        self.write_balancer_config.assert_called_once_with(expected)

    def test_unit_names_in_relation_data(self):
        self.relations_of_type.return_value = [
            {"private-address": "1.2.3.4",
             "port": 4242,
             "__unit__": "foo/1"},
            {"private-address": "1.2.3.5",
             "port": 4242,
             "__unit__": "foo/2"},
        ]
        expected = {
            "foo": ["1.2.3.4:4242", "1.2.3.5:4242"],
        }
        self.assertEqual(hooks.update_balancers(), expected)
        self.write_balancer_config.assert_called_once_with(expected)


class HelpersTest(TestCase):
    def setUp(self):
        super(HelpersTest, self).setUp()

        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
        super(HelpersTest, self).tearDown()

        shutil.rmtree(self.tempdir, ignore_errors=True)

    def read_fixture(self, basename):
        fixture = os.path.join(FIXTURES, basename)
        with original_open(fixture) as f:
            content = f.read()
        return content

    @patch('subprocess.call')
    def test_installs_packages(self, mock_call):
        mock_call.return_value = 'some result'

        result = hooks.apt_get_install('foo bar')

        self.assertEqual(result, 'some result')
        mock_call.assert_called_with(['apt-get', '-y', 'install', '-qq',
                                      'foo', 'bar'])

    @patch('subprocess.call')
    def test_installs_nothing_if_package_not_provided(self, mock_call):
        self.assertFalse(hooks.apt_get_install())
        self.assertFalse(mock_call.called)

    @patch('subprocess.call')
    def test_purges_packages(self, mock_call):
        mock_call.return_value = 'some result'

        result = hooks.apt_get_purge('foo bar')

        self.assertEqual(result, 'some result')
        mock_call.assert_called_with(['apt-get', '-y', 'purge', '-qq',
                                      'foo', 'bar'])

    @patch('subprocess.call')
    def test_purges_nothing_if_package_not_provided(self, mock_call):
        self.assertFalse(hooks.apt_get_purge())
        self.assertFalse(mock_call.called)

    @patch('subprocess.call')
    def test_starts_apache_successfully(self, mock_call):
        mock_call.return_value = 0
        action = 'start'

        self.assertTrue(hooks.service_apache2(action))
        mock_call.assert_called_with(['service', 'apache2', action])

    @patch('subprocess.call')
    def test_fails_to_start_apache(self, mock_call):
        mock_call.return_value = 1
        action = 'start'

        self.assertFalse(hooks.service_apache2(action))
        mock_call.assert_called_with(['service', 'apache2', action])

    @patch('subprocess.call')
    def test_checks_apache_successfully(self, mock_call):
        mock_call.return_value = 0

        self.assertTrue(hooks.service_apache2('check'))
        mock_call.assert_called_with(['/usr/sbin/apache2ctl', 'configtest'])

    @patch('subprocess.call')
    def test_fails_to_check_apache(self, mock_call):
        mock_call.return_value = 1

        self.assertFalse(hooks.service_apache2('check'))
        mock_call.assert_called_with(['/usr/sbin/apache2ctl', 'configtest'])

    @patch('subprocess.call')
    def test_fails_to_check_apache_with_another_return_value(self, mock_call):
        mock_call.return_value = 2

        self.assertFalse(hooks.service_apache2('check'))
        mock_call.assert_called_with(['/usr/sbin/apache2ctl', 'configtest'])

    @patch('subprocess.call')
    def test_does_nothing_if_action_not_provided(self, mock_call):
        self.assertIsNone(hooks.service_apache2())
        self.assertFalse(mock_call.called)

    @patch('subprocess.check_output')
    def test_runs_an_arbitrary_command(self, check_output):
        check_output.return_value = 'some result'

        self.assertEqual(hooks.run('foo', 1, 2, bar='baz'), 'some result')
        check_output.assert_called_with('foo', 1, 2, bar='baz')

    @patch('subprocess.check_output')
    @patch('sys.stdout')
    def test_prints_and_reraises_run_error(self, out, check_output):
        check_output.side_effect = RuntimeError('some error')

        self.assertRaises(RuntimeError, hooks.run, 'some command')
        self.assertEqual(out.write.mock_calls, [
            call('some error'),
            call('\n'),
        ])

    @patch('subprocess.call')
    @patch('hooks.log')
    @patch('hooks.service_apache2')
    @patch('os.path.exists')
    @patch('hooks.apt_get_install')
    def test_enables_a_module(self, apt_get_install, path_exists,
                              service_apache2, log, mock_call):
        module = 'foo'
        module_already_enabled = False
        module_available = False
        apache_check = True
        apache_reload = None
        module_installed = 0
        module_finally_enabled = 0

        path_exists.side_effect = [module_already_enabled, module_available]
        service_apache2.side_effect = [apache_check, apache_reload]
        apt_get_install.return_value = module_installed
        mock_call.return_value = module_finally_enabled

        result = hooks.enable_module(module)

        self.assertTrue(result)
        path_exists.assert_has_calls([
            call("/etc/apache2/mods-enabled/%s.load" % (module)),
            call("/etc/apache2/mods-available/%s.load" % (module))
        ])
        apt_get_install.assert_called_with("libapache2-mod-%s" % (module))
        mock_call.assert_called_with(['/usr/sbin/a2enmod', module])
        service_apache2.assert_has_calls([call('check'), call('reload')])
        self.assertFalse(log.called)

    @patch('subprocess.call')
    @patch('hooks.log')
    @patch('hooks.service_apache2')
    @patch('os.path.exists')
    @patch('hooks.apt_get_install')
    def test_doesnt_enable_if_module_not_provided(self, apt_get_install,
                                                  path_exists, service_apache2,
                                                  log, mock_call):
        module = None

        result = hooks.enable_module(module)

        self.assertTrue(result)
        self.assertFalse(apt_get_install.called)
        self.assertFalse(path_exists.called)
        self.assertFalse(service_apache2.called)
        self.assertFalse(log.called)
        self.assertFalse(mock_call.called)

    @patch('subprocess.call')
    @patch('hooks.log')
    @patch('hooks.service_apache2')
    @patch('os.path.exists')
    @patch('hooks.apt_get_install')
    def test_doesnt_enable_if_module_already_enabled(self, apt_get_install,
                                                     path_exists,
                                                     service_apache2, log,
                                                     mock_call):
        module = 'foo'
        module_already_enabled = True

        path_exists.return_value = module_already_enabled

        result = hooks.enable_module(module)

        self.assertTrue(result)
        path_exists.assert_called_with(
            "/etc/apache2/mods-enabled/%s.load" % (module))
        log.assert_called_with("Module already loaded: foo")
        self.assertFalse(apt_get_install.called)
        self.assertFalse(service_apache2.called)
        self.assertFalse(mock_call.called)

    @patch('subprocess.call')
    @patch('hooks.log')
    @patch('hooks.service_apache2')
    @patch('os.path.exists')
    @patch('hooks.apt_get_install')
    def test_fails_to_enable_if_module_not_installed(self, apt_get_install,
                                                     path_exists,
                                                     service_apache2, log,
                                                     mock_call):
        module = 'foo'
        module_already_enabled = False
        module_available = False
        module_installed = 1

        path_exists.side_effect = [module_already_enabled, module_available]
        apt_get_install.return_value = module_installed

        result = hooks.enable_module(module)

        self.assertFalse(result)
        path_exists.assert_has_calls([
            call("/etc/apache2/mods-enabled/%s.load" % (module)),
            call("/etc/apache2/mods-available/%s.load" % (module))
        ])
        apt_get_install.assert_called_with("libapache2-mod-%s" % (module))
        log.assert_called_with("Installing module %s failed" % (module))
        self.assertFalse(mock_call.called)
        self.assertFalse(service_apache2.called)

    @patch('subprocess.call')
    @patch('hooks.log')
    @patch('hooks.service_apache2')
    @patch('os.path.exists')
    @patch('hooks.apt_get_install')
    def test_fails_to_enable_if_enmod_fails(self, apt_get_install,
                                            path_exists, service_apache2,
                                            log, mock_call):
        module = 'foo'
        module_already_enabled = False
        module_available = False
        module_installed = 0
        module_finally_enabled = 1

        path_exists.side_effect = [module_already_enabled, module_available]
        apt_get_install.return_value = module_installed
        mock_call.return_value = module_finally_enabled

        result = hooks.enable_module(module)

        self.assertFalse(result)
        path_exists.assert_has_calls([
            call("/etc/apache2/mods-enabled/%s.load" % (module)),
            call("/etc/apache2/mods-available/%s.load" % (module))
        ])
        apt_get_install.assert_called_with("libapache2-mod-%s" % (module))
        mock_call.assert_called_with(['/usr/sbin/a2enmod', module])
        self.assertFalse(log.called)
        self.assertFalse(service_apache2.called)

    @patch('subprocess.call')
    @patch('hooks.log')
    @patch('hooks.service_apache2')
    @patch('os.path.exists')
    def test_disables_a_module(self, path_exists, service_apache2, log,
                               mock_call):
        module = 'foo'
        module_still_enabled = True
        apache_check = True
        apache_reload = None
        module_finally_disabled = 0

        path_exists.return_value = module_still_enabled
        service_apache2.side_effect = [apache_check, apache_reload]
        mock_call.return_value = module_finally_disabled

        result = hooks.disable_module(module)

        self.assertTrue(result)
        path_exists.assert_called_with(
            "/etc/apache2/mods-enabled/%s.load" % (module))
        mock_call.assert_called_with(['/usr/sbin/a2dismod', module])
        service_apache2.assert_has_calls([call('check'), call('reload')])
        self.assertFalse(log.called)

    @patch('subprocess.call')
    @patch('hooks.log')
    @patch('hooks.service_apache2')
    @patch('os.path.exists')
    def test_doest_disable_if_module_not_provided(self, path_exists,
                                                  service_apache2, log,
                                                  mock_call):
        module = None

        result = hooks.disable_module(module)

        self.assertTrue(result)
        self.assertFalse(path_exists.called)
        self.assertFalse(service_apache2.called)
        self.assertFalse(log.called)
        self.assertFalse(mock_call.called)

    @patch('subprocess.call')
    @patch('hooks.log')
    @patch('hooks.service_apache2')
    @patch('os.path.exists')
    def test_does_nothing_if_module_already_disabled(self, path_exists,
                                                     service_apache2, log,
                                                     mock_call):
        module = 'foo'
        module_still_enabled = False

        path_exists.return_value = module_still_enabled

        result = hooks.disable_module(module)

        self.assertTrue(result)
        path_exists.assert_called_with(
            "/etc/apache2/mods-enabled/%s.load" % (module))
        log.assert_called_with("Module already disabled: foo")

    @patch('subprocess.call')
    @patch('hooks.log')
    @patch('hooks.service_apache2')
    @patch('os.path.exists')
    def test_fails_to_disable_if_dismod_fails(self, path_exists,
                                              service_apache2, log, mock_call):
        module = 'foo'
        module_still_enabled = True
        apache_check = True
        apache_reload = None
        module_finally_disabled = 1

        path_exists.return_value = module_still_enabled
        service_apache2.side_effect = [apache_check, apache_reload]
        mock_call.return_value = module_finally_disabled

        result = hooks.disable_module(module)

        self.assertFalse(result)
        path_exists.assert_called_with(
            "/etc/apache2/mods-enabled/%s.load" % (module))
        mock_call.assert_called_with(['/usr/sbin/a2dismod', module])
        self.assertFalse(service_apache2.called)
        self.assertFalse(log.called)

    @patch('subprocess.call')
    @patch('hooks.is_apache24')
    @patch('hooks.config_get')
    @patch('hooks.log')
    def test_writes_balancer_config(self, log, config_get,
                                    is_apache24, mock_call):
        config_get.return_value = {
            'lb_balancer_timeout': 123,
        }
        balancer_config = {
            'foo': ['10.11.12.13'],
            'bar': ['10.11.12.14', '10.11.12.15'],
        }
        # Apache 2.4:
        mock_call.return_value = 0
        is_apache24.return_value = True
        with patch('hooks.default_apache24_config_dir', self.tempdir):
            hooks.write_balancer_config(balancer_config)
        for balancer in balancer_config.keys():
            basename = '%s.balancer' % balancer
            exp_path = os.path.join(FIXTURES, basename)
            res_path = os.path.join(self.tempdir, "{}.conf".format(basename))
            with open(exp_path) as exp, open(res_path) as res:
                self.assertEqual(exp.read(), res.read())
        mock_call.assert_called_with(['/usr/sbin/a2enconf', basename])

        # Apache 2.2:
        mock_call.reset_mock()
        is_apache24.return_value = False
        with patch('hooks.default_apache22_config_dir', self.tempdir):
            hooks.write_balancer_config(balancer_config)
        for balancer in balancer_config.keys():
            basename = '%s.balancer' % balancer
            exp_path = os.path.join(FIXTURES, basename)
            res_path = os.path.join(self.tempdir, basename)
            with open(exp_path) as exp, open(res_path) as res:
                self.assertEqual(exp.read(), res.read())
        # assert no external commands called
        self.assertItemsEqual(mock_call.call_args_list, [])


class HooksTest(TestCase):
    def setUp(self):
        super(HooksTest, self).setUp()
        self.executable_file = '/some/executable'
        self.unexecutable_file = '/some/unexecutable'
        self.is_a_file = True
        self.not_a_file = False
        self.is_executable = True
        self.not_executable = False
        self.dir_exists = True
        self.not_a_dir = False
        self.log_prefix = 'baz'
        self.log_path = '/tmp/pprint-%s.log' % self.log_prefix

    def tearDown(self):
        super(HooksTest, self).tearDown()
        if os.path.exists(self.log_path):
            os.remove(self.log_path)

    @patch('hooks.open')
    @patch('hooks.config_get')
    @patch('os.path.exists')
    @patch('os.mkdir')
    @patch('hooks.apt_get_install')
    @patch('hooks.log', MagicMock())
    @patch('hooks.apt_update')
    def test_installs_hook(
            self, apt_update, apt_get_install, mkdir, exists, config_get,
            open):
        exists.return_value = self.not_a_dir
        config_get.return_value = None
        apt_get_install.return_value = 'some result'

        result = hooks.install_hook()

        self.assertEqual(result, 'some result')
        exists.assert_called_with(hooks.default_apache2_service_config_dir)
        mkdir.assert_called_with(hooks.default_apache2_service_config_dir,
                                 0o600)
        apt_get_install.assert_has_calls([
            call('python-jinja2'),
            call('python-openssl'),
            call('python-pyasn1'),
            call('python-pyasn1-modules'),
            call('python-yaml'),
            call('apache2'),
        ])

    @patch('hooks.open')
    @patch('os.path.exists')
    @patch('os.mkdir')
    @patch('hooks.apt_get_install')
    @patch('hooks.log', MagicMock())
    @patch('hooks.apt_update')
    def test_install_hook_installs_extra_packages(
            self, apt_update, apt_get_install, mkdir, exists,
            open):
        exists.return_value = self.dir_exists
        c = {'extra_packages': 'extra', 'apt-source': '', 'apt-key-id': ''}
        config_get = MagicMock(wraps=c.get)
        apt_get_install.return_value = 'some result'

        with patch('hooks.config_get', config_get):
            result = hooks.install_hook()

        self.assertEqual(result, 'some result')
        apt_get_install.assert_has_calls([
            call('python-jinja2'),
            call('python-openssl'),
            call('python-pyasn1'),
            call('python-pyasn1-modules'),
            call('python-yaml'),
            call('apache2'),
            call('extra'),
        ])

    @patch('hooks.open')
    @patch('hooks.config_get')
    @patch('os.path.exists')
    @patch('os.mkdir')
    @patch('hooks.apt_get_install')
    @patch('hooks.log', MagicMock())
    @patch('hooks.apt_update')
    def test_doesnt_create_dir_to_install_hooks_if_not_needed(
            self, apt_update, apt_get_install, mkdir, exists, config_get,
            open):
        exists.return_value = self.dir_exists
        config_get.return_value = None
        apt_get_install.return_value = 'some result'

        result = hooks.install_hook()

        self.assertEqual(result, 'some result')
        exists.assert_called_with(hooks.default_apache2_service_config_dir)
        self.assertFalse(mkdir.called)
        apt_get_install.assert_has_calls([
            call('python-jinja2'),
            call('python-openssl'),
            call('python-pyasn1'),
            call('python-pyasn1-modules'),
            call('python-yaml'),
            call('apache2'),
        ])

    def test_dumps_data_into_file(self):
        data = {'foo': 'bar'}

        hooks.dump_data(data, self.log_prefix)

        with open(self.log_path) as f:
            self.assertEqual(f.read().strip(), pformat(data).strip())

    def test_dumps_nothing_if_data_not_provided(self):
        data = None

        hooks.dump_data(data, self.log_prefix)

        self.assertFalse(os.path.exists(self.log_path))

    @patch('hooks.relations_of_type')
    @patch('yaml.safe_load')
    @patch('hooks.log')
    def test_gets_reverseproxy_data(self, log, load, relations_of_type):
        relation_data = [
            {'port': 1234,
             'private-address': '10.11.12.13',
             'all_services': '/some/yaml/file',
             '__unit__': 'foo-unit/1',
             },
            {'port': 1234,
             'private-address': '10.11.12.14',
             'all_services': '/some/yaml/file2',
             '__unit__': 'foo-unit/2',
             },
            {'port': 3214,
             'private-address': '10.11.12.13',
             'all_services': '/some/yaml/file3',
             '__unit__': 'bar-unit/1',
             },
        ]
        yaml_content = [
            {
                'service_name': 'some-service',
                'service_port': '2345',
            },
        ]

        relations_of_type.return_value = relation_data
        load.return_value = yaml_content

        result = hooks.get_reverseproxy_data(relation='baz-proxy')

        self.assertEqual(result, {
            'barunit': '10.11.12.13:3214',
            'barunit_all_services': '/some/yaml/file3',
            'barunit_port': 3214,
            'barunit_private_address': '10.11.12.13',
            'barunit_someservice': '10.11.12.13:2345',
            'foounit': '10.11.12.13:1234',
            'foounit_all_services': '/some/yaml/file',
            'foounit_port': 1234,
            'foounit_private_address': '10.11.12.13',
            'foounit_someservice': '10.11.12.13:2345',
        })
        relations_of_type.assert_called_with('baz-proxy')
        self.assertEqual(sorted(load.mock_calls), sorted([
            call('/some/yaml/file'),
            call('/some/yaml/file3'),
        ]))
        self.assertEqual(sorted(log.mock_calls), sorted([
            call('unit_type: barunit'),
            call('unit_type: foounit'),
            call('unit_type: foounit'),
        ]))

    @patch('hooks.relations_of_type')
    @patch('yaml.safe_load')
    @patch('hooks.log')
    def test_truncates_reverseproxy_data_if_unit_has_no_port(
            self, log, load, relations_of_type):
        relation_data = [
            {'port': 1234,
             'private-address': '10.11.12.13',
             'all_services': '/some/yaml/file',
             '__unit__': 'foo-unit/1',
             },
            {'private-address': '10.11.12.13',
             'all_services': '/some/yaml/file3',
             '__unit__': 'bar-unit/1',
             },
        ]

        relations_of_type.return_value = relation_data

        result = hooks.get_reverseproxy_data(relation='baz-proxy')

        self.assertEqual(result, {'foounit': '10.11.12.13:1234',
                                  'foounit_all_services': '/some/yaml/file',
                                  'foounit_port': 1234,
                                  'foounit_private_address': '10.11.12.13'})
        relations_of_type.assert_called_with('baz-proxy')
        self.assertTrue(load.called)

    @patch('hooks.relations_of_type')
    @patch('yaml.safe_load')
    @patch('hooks.log')
    def test_truncates_reverseproxy_data_if_no_data_available(
            self, log, load, relations_of_type):
        relations_of_type.return_value = []

        result = hooks.get_reverseproxy_data(relation='baz-proxy')

        self.assertEqual(result, {})
        relations_of_type.assert_called_with('baz-proxy')
        self.assertFalse(load.called)
