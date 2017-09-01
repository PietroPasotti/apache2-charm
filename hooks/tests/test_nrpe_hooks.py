from testtools import TestCase
from mock import patch

import hooks


class NRPERelationTest(TestCase):
    """Tests for the update_nrpe_checks hook."""

    @patch('hooks.nrpe.NRPE')
    def test_update_nrpe_with_check(self, mock_nrpe):
        nrpe = mock_nrpe.return_value
        nrpe.config = {
            'nagios_check_http_params': '-u foo -H bar',
        }
        hooks.update_nrpe_checks()
        nrpe.add_check.assert_called_once_with(
            shortname='vhost',
            description='Check Virtual Host',
            check_cmd='check_http -u foo -H bar'
        )
        nrpe.write.assert_called_once_with()

    @patch('hooks.nrpe.NRPE')
    def test_update_nrpe_no_check(self, mock_nrpe):
        nrpe = mock_nrpe.return_value
        nrpe.config = {}
        hooks.update_nrpe_checks()
        self.assertFalse(nrpe.add_check.called)
        nrpe.write.assert_called_once_with()
