from testtools import TestCase
import hooks
from base64 import b64encode
from mock import patch, call
import yaml
import tempfile
import os
import shutil


class CreateVhostTest(TestCase):

    def setUp(self):
        super(CreateVhostTest, self).setUp()
        self.dirname = tempfile.mkdtemp()
        os.mkdir("%s/sites-enabled" % self.dirname)
        os.mkdir("%s/sites-available" % self.dirname)
        os.mkdir("%s/conf.d" % self.dirname)
        hooks.default_apache_base_dir = self.dirname
        hooks.default_apache22_config_dir = "%s/conf.d" % self.dirname
        hooks.default_apache24_config_dir = "%s/conf-available" % self.dirname

    def tearDown(self):
        super(CreateVhostTest, self).tearDown()
        if os.path.exists(self.dirname):
            shutil.rmtree(self.dirname)

    @patch('hooks.log')
    @patch('subprocess.call')
    def test_create_vhost_missing_template(
            self, mock_call, mock_log):
        """Create a vhost file, check contents."""
        hooks.create_vhost(80)
        mock_log.assert_called_once_with(
            "Vhost Template not provided, not configuring: %s" % 80)
        self.assertEqual(
            len(os.listdir("%s/%s" % (self.dirname, "sites-available"))), 0)

    @patch('hooks.log')
    @patch('subprocess.call')
    def test_create_vhost_template_through_config_no_protocol(
            self, mock_call, mock_log):
        """Create a vhost file, check contents."""
        template = b64encode("http://{{ variable }}/")
        config_data = {
            "template": template,
            "servername": "test_only"}
        relationship_data = {
            "variable": "fantastic"}
        hooks.create_vhost(
            80, config_data=config_data, config_key="template",
            relationship_data=relationship_data)
        filename = hooks.site_filename("test_only_80")
        self.assertTrue(os.path.exists(filename))
        with open(filename, 'r') as file:
            contents = file.read()
        self.assertEqual(contents, 'http://fantastic/')
        self.assertEqual(
            len(os.listdir("%s/%s" % (self.dirname, "sites-available"))), 1)

    @patch('hooks.log')
    @patch('subprocess.call')
    def test_create_vhost_template_through_config_with_protocol(
            self, mock_call, mock_log):
        """Create a vhost file, check contents."""
        template = b64encode("http://{{ variable }}/")
        config_data = {
            "template": template,
            "servername": "test_only"}
        relationship_data = {
            "variable": "fantastic"}
        hooks.create_vhost(
            80, config_data=config_data, config_key="template",
            protocol='http', relationship_data=relationship_data)
        filename = hooks.site_filename("test_only_http")
        self.assertTrue(os.path.exists(filename))
        with open(filename, 'r') as file:
            contents = file.read()
        self.assertEqual(contents, 'http://fantastic/')
        self.assertEqual(
            len(os.listdir("%s/%s" % (self.dirname, "sites-available"))), 1)

    @patch('hooks.log')
    @patch('subprocess.call')
    def test_create_vhost_template_directly(
            self, mock_call, mock_log):
        """Create a vhost file, check contents."""
        template = b64encode("http://{{ variable }}/")
        config_data = {
            "servername": "test_only"}
        relationship_data = {
            "variable": "fantastic"}
        hooks.create_vhost(
            80, template_str=template, config_data=config_data,
            config_key="template", relationship_data=relationship_data)
        filename = hooks.site_filename("test_only_80")
        self.assertTrue(os.path.exists(filename))
        with open(filename, 'r') as file:
            contents = file.read()
        self.assertEqual(contents, 'http://fantastic/')
        self.assertEqual(
            len(os.listdir("%s/%s" % (self.dirname, "sites-available"))), 1)


class VhostConfigRelationTest(TestCase):
    @patch('hooks.service_apache2')
    @patch('hooks.relation_ids')
    @patch('hooks.relations_of_type')
    @patch('hooks.get_reverseproxy_data')
    @patch('hooks.config_get')
    def test_vhost_config_relation_changed_no_relation_data(
            self, mock_config_get, mock_relation_get,
            mock_relations_of_type, mock_relation_ids,
            mock_service_apache2):
        """No relation data, do nothing."""
        mock_relation_get.return_value = None
        hooks.update_vhost_config_relation()

    @patch('hooks.relations_of_type')
    @patch('hooks.service_apache2')
    @patch('hooks.config_get')
    @patch('hooks.get_reverseproxy_data')
    @patch('hooks.log')
    def test_vhost_config_relation_changed_vhost_ports_only(
            self, mock_log, mock_reverseproxy, mock_config_get,
            mock_service_apache2, mock_relations_of_type):
        """vhost_ports only specified, hook should exit with error"""
        mock_relations_of_type.return_value = [
            {'vhosts': yaml.dump([{'port': "5555"}])}]
        mock_config_get.return_value = {}
        self.assertRaisesRegex(
            KeyError, "template", hooks.update_vhost_config_relation)

    @patch('hooks.log')
    @patch('hooks.relation_ids')
    @patch('hooks.relations_of_type')
    @patch('hooks.config_get')
    @patch('hooks.get_reverseproxy_data')
    @patch('hooks.create_vhost')
    @patch('hooks.service_apache2')
    @patch('hooks.relation_set')
    def test_vhost_config_relation_changed_vhost_ports_single(
            self, mock_relation_set, mock_service_apache2,
            mock_create_vhost, mock_reverseproxy, mock_config_get,
            mock_relations_of_type, mock_relation_ids, mock_log):
        """A single vhost entry is created."""
        mock_relation_ids.return_value = ["testonly"]
        rel = {"vhosts": yaml.dump([{
            'port': '80',
            'template': b64encode("foo")
        }])}
        config_data = {
            "servername": "unused",
            "ssl_certlocation": "unused",
            "ssl_keylocation": "unused",
            "ssl_cert": ""}
        mock_config_get.return_value = config_data
        mock_relations_of_type.return_value = [rel]
        hooks.update_vhost_config_relation()
        mock_create_vhost.assert_called_once_with(
            "80",
            template_str=b64encode("foo"),
            config_data=config_data,
            relationship_data={}
        )

    @patch('hooks.log')
    @patch('hooks.relation_ids')
    @patch('hooks.relations_of_type')
    @patch('hooks.config_get')
    @patch('hooks.get_reverseproxy_data')
    @patch('hooks.create_vhost')
    @patch('hooks.service_apache2')
    @patch('hooks.relation_set')
    def test_vhost_config_relation_changed_vhost_ports_multi(
            self, mock_relation_set, mock_service_apache2,
            mock_create_vhost, mock_reverseproxy, mock_config_get,
            mock_relations_of_type, mock_relation_ids, mock_log):
        """Multiple vhost entries are created."""
        mock_relation_ids.return_value = ["testonly"]
        rel = {"vhosts": yaml.dump([
            {'port': "80", 'template': b64encode("80")},
            {'port': "443", 'template': b64encode("443")},
            {'port': "444", 'template': b64encode("444")}])}
        mock_relations_of_type.return_value = [rel]
        config_data = {
            "servername": "unused",
            "ssl_certlocation": "unused",
            "ssl_keylocation": "unused",
            "ssl_cert": ""}
        mock_config_get.return_value = config_data
        hooks.update_vhost_config_relation()
        mock_create_vhost.assert_has_calls([
            call("80", template_str=b64encode("80"),
                 config_data=config_data, relationship_data={}),
            call().__nonzero__(),
            call("443", template_str=b64encode("443"),
                 config_data=config_data, relationship_data={}),
            call().__nonzero__(),
            call("444", template_str=b64encode("444"),
                 config_data=config_data, relationship_data={}),
            call().__nonzero__(),
            ])
        self.assertEqual(mock_create_vhost.call_count, 3)
