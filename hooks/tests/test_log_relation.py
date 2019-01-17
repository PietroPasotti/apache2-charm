from testtools import TestCase
import mock
import hooks
hooks.log = mock.MagicMock()


class TestLogRelation(TestCase):

    @mock.patch('hooks.config_get')
    def test_get_log_files_no_raise(self, config_get):
        'does not raise'
        hooks.get_log_files()

    @mock.patch('hooks.config_get')
    def test_get_log_files_parses(self, config_get):
        'parses files for real'
        config_get.return_value = {'servername': 'hello'}
        m = mock.mock_open(read_data='''junk
            CustomLog /var/log/apache2/access.log combined\n")
            ErrorLog /var/log/apache2/error.log\n")
            junk\n"''')

        with mock.patch('hooks.open', m, create=True):
            access_logs, error_logs = hooks.get_log_files()
            self.assertEqual('/var/log/apache2/access.log', access_logs[0])
            self.assertEqual('/var/log/apache2/error.log', error_logs[0])

    @mock.patch('hooks.relation_ids')
    @mock.patch('hooks.relation_set')
    def test_log_relation_joined(self, relation_set, relation_ids):
        relation_ids.return_value = ['logs:1']
        with mock.patch('hooks.get_log_files') as get_log_files:
            get_log_files.return_value = ['myaccess_log'], ['myerror_log']
            hooks.logs_relation_joined()
            self.assertTrue(relation_set.called)
            self.assertEqual({'files': 'myaccess_log\nmyerror_log',
                              'types': 'apache_access\napache_error',
                              },
                             relation_set.call_args[1]['relation_settings'])

    @mock.patch('hooks.relation_ids')
    @mock.patch('hooks.relation_set')
    def test_log_relation_joined_config_changed(self,
                                                relation_set,
                                                relation_ids):
        relation_ids.return_value = ['logs/0']
        with mock.patch('hooks.get_log_files') as get_log_files:
            get_log_files.return_value = ['myaccess_log'], ['myerror_log']
            hooks.logs_relation_joined()
            self.assertTrue(relation_set.called)
            self.assertEqual({'files': 'myaccess_log\nmyerror_log',
                              'types': 'apache_access\napache_error',
                              },
                             relation_set.call_args[1]['relation_settings'])
