from testtools import TestCase
import hooks
import base64
import tempfile
from mock import patch


class CreateVhostTest(TestCase):
    def setUp(self):
        super(CreateVhostTest, self).setUp()

    @patch('hooks.log')
    @patch('hooks.close_port')
    def test_create_vhost_no_template(self, mock_close_port, mock_log):
        """User did not specify a template, error logged."""
        hooks.create_vhost("80")
        mock_log.assert_called_once_with(
            'Vhost Template not provided, not configuring: 80')

    @patch('hooks.close_port')
    @patch('hooks.site_filename')
    @patch('hooks.open_port')
    @patch('hooks.subprocess.call')
    def test_create_vhost_template_name_port(
            self, mock_call, mock_open_port, mock_site_filename,
            mock_close_port):
        """Check that name generated is sane as a port."""
        config = {"servername": "unused"}
        file = tempfile.NamedTemporaryFile()
        filename = file.name
        mock_site_filename.return_value = filename
        hooks.create_vhost(
            "80",
            config_data=config,
            template_str=base64.b64encode("foo"))
        mock_site_filename.assert_called_once_with("unused_80")

    @patch('hooks.close_port')
    @patch('hooks.site_filename')
    @patch('hooks.open_port')
    @patch('hooks.subprocess.call')
    def test_create_vhost_template_name_protocol(
            self, mock_call, mock_open_port, mock_site_filename,
            mock_close_port):
        """Check that name generated is sane as a protocol."""
        config = {"servername": "unused"}
        file = tempfile.NamedTemporaryFile()
        filename = file.name
        mock_site_filename.return_value = filename
        hooks.create_vhost(
            "80",
            protocol="httpfoo",
            config_data=config,
            template_str=base64.b64encode("foo"))
        mock_site_filename.assert_called_once_with("unused_httpfoo")

    @patch('hooks.close_port')
    @patch('hooks.site_filename')
    @patch('hooks.open_port')
    @patch('hooks.subprocess.call')
    def test_create_vhost_template(
            self, mock_call, mock_open_port, mock_site_filename,
            mock_close_port):
        """
        Template passed in as string.

        Verify relationship and config inform template as well.
        """
        template = ("{{servername}} {{ foo }}")
        config = {"servername": "test_only"}
        relationship = {"foo": "bar"}
        file = tempfile.NamedTemporaryFile()
        filename = file.name
        mock_site_filename.return_value = filename
        hooks.create_vhost(
            "80",
            config_data=config,
            relationship_data=relationship,
            template_str=base64.b64encode(template))
        with open(filename, 'r') as f:
            contents = f.read()
        self.assertEqual(contents, "test_only bar")

    @patch('hooks.close_port')
    @patch('hooks.site_filename')
    @patch('hooks.open_port')
    @patch('hooks.subprocess.call')
    def test_create_vhost_template_config(
            self, mock_call, mock_open_port, mock_site_filename,
            mock_close_port):
        """Template passed in as config setting."""
        template = ("one\n"
                    "two\n"
                    "three")
        config = {"servername": "unused",
                  "vhost_template": base64.b64encode(template)}
        file = tempfile.NamedTemporaryFile()
        filename = file.name
        mock_site_filename.return_value = filename
        hooks.create_vhost(
            "80",
            config_key="vhost_template",
            config_data=config)
        with open(filename, 'r') as f:
            contents = f.read()
        self.assertEqual(contents, template)

    @patch('hooks.close_port')
    @patch('hooks.site_filename')
    @patch('hooks.open_port')
    @patch('hooks.subprocess.call')
    def test_create_vhost_template_config_template_vars(
            self, mock_call, mock_open_port, mock_site_filename,
            mock_close_port):
        """Template passed in as config setting."""
        template = ("one\n"
                    "two\n"
                    "{{ extra }}")
        expected = ("one\n"
                    "two\n"
                    "three")
        config = {"servername": "unused",
                  "vhost_template_vars": "{'extra': 'three'}",
                  "vhost_template": base64.b64encode(template)}
        file = tempfile.NamedTemporaryFile()
        filename = file.name
        mock_site_filename.return_value = filename
        hooks.create_vhost(
            "80",
            config_key="vhost_template",
            config_data=config)
        with open(filename, 'r') as f:
            contents = f.read()
        self.assertEqual(contents, expected)
