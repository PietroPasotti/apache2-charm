#!/usr/bin/env python2

import errno
import os
import re
import socket
import subprocess
import sys
import yaml
import base64
import grp
import pwd
import shutil
import os.path
import ast

from charmhelpers.core.hookenv import (
    config as orig_config_get,
    close_port,
    log,
    open_port,
    relation_set,
    relation_ids,
    relations_of_type,
    status_set,
    unit_get
)
from charmhelpers.contrib.charmsupport import nrpe
from charmhelpers.fetch import apt_update, add_source

###############################################################################
# Global variables
###############################################################################
default_apache2_service_config_dir = "/var/run/apache2"
service_affecting_packages = ['apache2']
default_apache22_config_dir = "/etc/apache2/conf.d"
default_apache24_config_dir = "/etc/apache2/conf-available"
default_apache_base_dir = "/etc/apache2"

juju_warning_header = """#
#    "             "
#  mmm   m   m   mmm   m   m
#    #   #   #     #   #   #
#    #   #   #     #   #   #
#    #   "mm"#     #   "mm"#
#    #             #
#  ""            ""
# This file is managed by Juju. Do not make local changes.
#"""


###############################################################################
# Supporting functions
###############################################################################

def apt_get_install(packages=None):
    """Install packages."""
    if packages is None:
        return False
    cmd_line = ['apt-get', '-y', 'install', '-qq']
    for pkg in re.split(' |,', packages):
        cmd_line.append(pkg)
    return subprocess.call(cmd_line)


def ensure_package_status(packages, status):
    if status in ['install', 'hold']:
        selections = ''.join(['{} {}\n'.format(package, status)
                              for package in packages])
        dpkg = subprocess.Popen(['dpkg', '--set-selections'],
                                stdin=subprocess.PIPE)
        dpkg.communicate(input=selections)


# -----------------------------------------------------------------------------
# apt_get_purge( package ):  Purges a package
# -----------------------------------------------------------------------------
def apt_get_purge(packages=None):
    if packages is None:
        return False
    cmd_line = ['apt-get', '-y', 'purge', '-qq']
    for pkg in re.split(' |,', packages):
        cmd_line.append(pkg)
    return subprocess.call(cmd_line)


# -----------------------------------------------------------------------------
# service_apache2:  Convenience function to start/stop/restart/reload
#                   the apache2 service
# -----------------------------------------------------------------------------
def service_apache2(action=None):
    if action is None:
        return
    elif action == "check":
        args = ['/usr/sbin/apache2ctl', 'configtest']
    else:
        args = ['service', 'apache2', action]
    ret_val = subprocess.call(args)
    return ret_val == 0


def run(command, *args, **kwargs):
    try:
        output = subprocess.check_output(command, *args, **kwargs)
        return output
    except Exception as e:
        print(e)
        raise


def enable_module(module=None):
    if module is None:
        return True
    if os.path.exists("/etc/apache2/mods-enabled/%s.load" % (module)):
        log("Module already loaded: %s" % module)
        return True
    if not os.path.exists("/etc/apache2/mods-available/%s.load" % (module)):
        return_value = apt_get_install("libapache2-mod-%s" % (module))
        if return_value != 0:
            log("Installing module %s failed" % (module))
            return False
    return_value = subprocess.call(['/usr/sbin/a2enmod', module])
    if return_value != 0:
        return False
    if service_apache2("check"):
        service_apache2("reload")
        return True


def disable_module(module=None):
    if module is None:
        return True
    if not os.path.exists("/etc/apache2/mods-enabled/%s.load" % (module)):
        log("Module already disabled: %s" % module)
        return True
    return_value = subprocess.call(['/usr/sbin/a2dismod', module])
    if return_value != 0:
        return False
    if service_apache2("check"):
        service_apache2("reload")
        return True


def is_apache24():
    return os.path.exists("/usr/sbin/a2enconf")


def site_filename(name, enabled=False):
    if enabled:
        sites_dir = "%s/sites-enabled" % default_apache_base_dir
    else:
        sites_dir = "%s/sites-available" % default_apache_base_dir

    if is_apache24():
        return "{}/{}.conf".format(sites_dir, name)
    else:
        return "{}/{}".format(sites_dir, name)


def conf_filename(name):
    """Return an apache2 config filename path, as:
      2.4: /etc/apache2/conf-available/foo.conf
      2.2: /etc/apache2/conf.d/foo
    """
    if is_apache24():
        return "{}/{}.conf".format(default_apache24_config_dir, name)
    else:
        return "{}/{}".format(default_apache22_config_dir, name)


def conf_enable(name):
    "Enable apache2 config without reloading service"
    if is_apache24():
        return subprocess.call(['/usr/sbin/a2enconf', name]) == 0
    # no-op otherwise
    return True


def conf_disable(name):
    "Disable apache2 config without reloading service"
    if is_apache24():
        return subprocess.call(['/usr/sbin/a2disconf', name]) == 0
    # no-op otherwise
    return True


def gen_selfsigned_cert(config, cert_file, key_file):
    """
    Create a self-signed certificate.

    @param config: charm data from config-get
    @param cert_file: destination path of generated certificate
    @param key_file: destination path of generated private key
    """
    os.environ['OPENSSL_CN'] = config['servername']
    os.environ['OPENSSL_PUBLIC'] = unit_get("public-address")
    os.environ['OPENSSL_PRIVATE'] = unit_get("private-address")
    run(
        ['openssl', 'req', '-new', '-x509', '-nodes',
         '-days', '3650', '-config',
         os.path.join(os.environ['CHARM_DIR'], 'data', 'openssl.cnf'),
         '-keyout', key_file, '-out', cert_file])


def is_selfsigned_cert_stale(config, cert_file, key_file):
    """
    Do we need to generate a new self-signed cert?

    @param config: charm data from config-get
    @param cert_file: destination path of generated certificate
    @param key_file: destination path of generated private key
    """
    # Basic Existence Checks
    if not os.path.exists(cert_file):
        return True
    if not os.path.exists(key_file):
        return True

    # Common Name
    from OpenSSL import crypto
    cert = crypto.load_certificate(
        crypto.FILETYPE_PEM, open(cert_file, 'r').read())
    cn = cert.get_subject().commonName
    if config['servername'] != cn:
        return True

    # Subject Alternate Name -- only trusty+ support this
    try:
        from pyasn1.codec.der import decoder
        from pyasn1_modules import rfc2459
    except ImportError:
        log("Cannot check subjAltName on <= 12.04, skipping.")
        return False
    cert_addresses = set()
    unit_addresses = set(
        [unit_get("public-address"), unit_get("private-address")])
    for i in range(0, cert.get_extension_count()):
        extension = cert.get_extension(i)
        try:
            names = decoder.decode(
                extension.get_data(), asn1Spec=rfc2459.SubjectAltName())[0]
            for name in names:
                cert_addresses.add(str(name.getComponent()))
        except Exception:
            pass
    if cert_addresses != unit_addresses:
        log("subjAltName: Cert (%s) != Unit (%s), assuming stale" % (
            cert_addresses, unit_addresses))
        return True

    return False


def _get_key_file_location(config_data):
    """Look at the config, generate the key file location."""
    key_file = None
    if config_data['ssl_keylocation']:
        key_file = '/etc/ssl/private/%s' % \
            (config_data['ssl_keylocation'].rpartition('/')[2])
    return key_file


def _get_cert_file_location(config_data):
    """Look at the config, generate the cert file location."""
    cert_file = None
    if config_data['ssl_certlocation']:
        cert_file = '/etc/ssl/certs/%s' % \
            (config_data['ssl_certlocation'].rpartition('/')[2])
    return cert_file


def _get_chain_file_location(config_data):
    """Look at the config, generate the chain file location."""
    chain_file = None
    if config_data['ssl_chainlocation']:
        chain_file = '/etc/ssl/certs/%s' % \
            (config_data['ssl_chainlocation'].rpartition('/')[2])
    return chain_file


def config_get(scope=None):
    """
    Wrapper around charm helper's config_get to replace an empty servername
    with the public-address.
    """
    result = orig_config_get(scope)
    if scope == "servername" and len(result) == 0:
        result = unit_get("public-address")
    elif isinstance(result, dict) and result.get("servername", "") == "":
        result["servername"] = unit_get("public-address")
    return result


def install_hook():
    status_set("maintenance", "installing unit")
    apt_source = config_get('apt-source') or ''
    apt_key_id = config_get('apt-key-id') or False
    if apt_source and apt_key_id:
        print(apt_source + " and " + apt_key_id)
        add_source(apt_source, apt_key_id)
        open('config.apt-source', 'w').write(apt_source)
    if not os.path.exists(default_apache2_service_config_dir):
        os.mkdir(default_apache2_service_config_dir, 0o600)
    apt_update(fatal=True)
    apt_get_install("python-jinja2")
    apt_get_install("python-openssl")
    apt_get_install("python-pyasn1")
    apt_get_install("python-pyasn1-modules")
    apt_get_install("python-yaml")
    install_status = apt_get_install("apache2")
    if install_status == 0:
        ensure_package_status(service_affecting_packages,
                              config_get('package_status'))
    ensure_extra_packages()
    # the apache2 deb does not yet have http2 module in mods-available. Add it.
    open('/etc/apache2/mods-available/http2.load', 'w').write(
        'LoadModule http2_module /usr/lib/apache2/modules/mod_http2.so')
    open('/etc/apache2/mods-available/http2.conf', 'w').write(
        '''<IfModule http2_module>
  ProtocolsHonorOrder On
  Protocols h2 http/1.1
</IfModule>
''')
    return install_status


def ensure_extra_packages():
    extra = str(config_get('extra_packages'))
    if extra:
        install_status = apt_get_install(extra)
        if install_status == 0:
            ensure_package_status([_f for _f in extra.split(' ') if _f],
                                  config_get('package_status'))


def dump_data(data2dump, log_prefix):
    log_file = '/tmp/pprint-%s.log' % (log_prefix)
    if data2dump is not None:
        logFile = open(log_file, 'w')
        import pprint
        pprint.pprint(data2dump, logFile)
        logFile.close()


def get_reverseproxy_data(relation='reverseproxy'):
    relation_data = relations_of_type(relation)
    reverseproxy_data = {}
    if relation_data is None or len(relation_data) == 0:
        return reverseproxy_data
    for unit_data in relation_data:
        unit_name = unit_data["__unit__"]
        if 'port' not in unit_data:
            return reverseproxy_data
        # unit_name: <service-name>-<unit_number>
        # jinja2 templates require python-type variables, remove all characters
        # that do not comply
        unit_type = re.sub(r'(.*)/[0-9]*', r'\1', unit_name)
        unit_type = re.sub('[^a-zA-Z0-9_]*', '', unit_type)
        log('unit_type: %s' % unit_type)

        host = unit_data['private-address']
        if unit_type in reverseproxy_data:
            continue
        for config_setting in unit_data.keys():
            if config_setting in ("__unit__", "__relid__"):
                continue
            config_key = '%s_%s' % (unit_type,
                                    config_setting.replace("-", "_"))
            config_key = re.sub('[^a-zA-Z0-9_]*', '', config_key)
            reverseproxy_data[config_key] = unit_data[
                config_setting]
            reverseproxy_data[unit_type] = '%s:%s' % (
                host, unit_data['port'])
        if 'all_services' in unit_data:
            service_data = yaml.safe_load(unit_data['all_services'])
            for service_item in service_data:
                service_name = service_item['service_name']
                service_port = service_item['service_port']
                service_key = '%s_%s' % (unit_type, service_name)
                service_key = re.sub('[^a-zA-Z0-9_]*', '', service_key)
                reverseproxy_data[service_key] = '%s:%s' % (host, service_port)
    return reverseproxy_data


def update_balancers():
    relation_data = relations_of_type('balancer')
    if relation_data is None or len(relation_data) == 0:
        log("No relation data, exiting.")
        return

    unit_dict = {}
    for unit_data in relation_data:
        unit_name = unit_data["__unit__"]
        if "port" not in unit_data:
            log("No port in relation data for '%s', skipping." % unit_name)
            continue
        port = unit_data["port"]
        if "private-address" not in unit_data:
            log("No private-address in relation data for '%s', skipping." %
                unit_name)
            continue
        host = unit_data['private-address']

        if "all_services" in unit_data:
            service_data = yaml.safe_load(unit_data[
                "all_services"])
            for service_item in service_data:
                service_port = service_item["service_port"]
                current_units = unit_dict.setdefault(
                    service_item["service_name"], [])
                current_units.append("%s:%s" % (host, service_port))
        else:
            if "sitenames" in unit_data:
                unit_types = unit_data["sitenames"].split()
            else:
                unit_types = (re.sub(r"(.*)/[0-9]*", r"\1", unit_name),)

            for unit_type in unit_types:
                current_units = unit_dict.setdefault(unit_type, [])
                current_units.append("%s:%s" % (host, port))

    if not unit_dict:
        return

    write_balancer_config(unit_dict)
    return unit_dict


def write_balancer_config(unit_dict):
    config_data = config_get()

    from jinja2 import Environment, FileSystemLoader
    template_env = Environment(loader=FileSystemLoader(os.path.join(
        os.environ['CHARM_DIR'], 'data')))
    for balancer_name in unit_dict.keys():
        balancer_host_file = conf_filename('{}.balancer'.format(balancer_name))
        templ_vars = {
            'balancer_name': balancer_name,
            'balancer_addresses': unit_dict[balancer_name],
            'lb_balancer_timeout': config_data['lb_balancer_timeout'],
        }
        template = template_env.get_template(
            'balancer.template').render(templ_vars)
        log("Writing file: %s with data: %s" % (balancer_host_file,
                                                templ_vars))
        with open(balancer_host_file, 'w') as balancer_config:
            balancer_config.write(str(template))
        conf_enable('{}.balancer'.format(balancer_name))


def update_nrpe_checks():
    nrpe_compat = nrpe.NRPE()
    conf = nrpe_compat.config
    check_http_params = conf.get('nagios_check_http_params')
    if check_http_params:
        nrpe_compat.add_check(
            shortname='vhost',
            description='Check Virtual Host',
            check_cmd='check_http %s' % check_http_params
        )
    nrpe_compat.write()


def create_mpm_workerfile():
    config_data = config_get()
    mpm_workerfile = conf_filename('000mpm-worker')
    from jinja2 import Environment, FileSystemLoader
    template_env = Environment(loader=FileSystemLoader(os.path.join(
        os.environ['CHARM_DIR'], 'data')))
    templ_vars = {
        'mpm_type': config_data['mpm_type'],
        'mpm_startservers': config_data['mpm_startservers'],
        'mpm_minsparethreads': config_data['mpm_minsparethreads'],
        'mpm_maxsparethreads': config_data['mpm_maxsparethreads'],
        'mpm_threadlimit': config_data['mpm_threadlimit'],
        'mpm_threadsperchild': config_data['mpm_threadsperchild'],
        'mpm_serverlimit': config_data['mpm_serverlimit'],
        'mpm_maxclients': config_data['mpm_maxclients'],
        'mpm_maxrequestsperchild': config_data['mpm_maxrequestsperchild'],
    }
    template = \
        template_env.get_template('mpm_worker.template').render(templ_vars)
    with open(mpm_workerfile, 'w') as mpm_config:
        mpm_config.write(str(template))
    conf_enable('000mpm-worker')


def create_security():
    config_data = config_get()
    securityfile = conf_filename('security')
    from jinja2 import Environment, FileSystemLoader
    template_env = Environment(loader=FileSystemLoader(os.path.join(
        os.environ['CHARM_DIR'], 'data')))
    templ_vars = {
        'juju_warning_header': juju_warning_header,
        'server_tokens': config_data['server_tokens'],
        'server_signature': config_data['server_signature'],
        'trace_enabled': config_data['trace_enabled'],
        'ssl_protocol': config_data['ssl_protocol'],
        'ssl_honor_cipher_order': config_data['ssl_honor_cipher_order'],
        'ssl_cipher_suite': config_data['ssl_cipher_suite'],
        'is_apache24': is_apache24(),
    }
    template = \
        template_env.get_template('security.template').render(templ_vars)
    with open(securityfile, 'w') as security_config:
        security_config.write(str(template))
    conf_enable('security')


def ship_logrotate_conf():
    config_data = config_get()
    logrotate_file = '/etc/logrotate.d/apache2'
    from jinja2 import Environment, FileSystemLoader
    template_env = Environment(loader=FileSystemLoader(os.path.join(
        os.environ['CHARM_DIR'], 'data')))
    templ_vars = {
        'juju_warning_header': juju_warning_header,
        'logrotate_rotate': config_data['logrotate_rotate'],
        'logrotate_count': config_data['logrotate_count'],
        'logrotate_dateext': config_data['logrotate_dateext'],
    }
    template = template_env.get_template('logrotate.conf.template').render(
        templ_vars)
    with open(logrotate_file, 'w') as logrotate_conf:
        logrotate_conf.write(str(template))


def create_vhost(port, protocol=None, config_key=None, template_str=None,
                 config_data={}, relationship_data={}):
    """
    Create and enable a vhost in apache.

    @param port: port on which to listen (int)
    @param protocol: used to name the vhost file intelligently.  If not
        specified the port will be used instead. (ex: http, https)
    @param config_key: key in the configuration to look up to
        retrieve the template.
    @param template_str: The template itself as a string.
    @param config_data: juju get-config configuration data.
    @param relationship_data: if in a relationship, pass in the appropriate
        structure.  This will be used to inform the template.
    """
    if protocol is None:
        protocol = str(port)
    if template_str is None:
        if not config_key or not config_data[config_key]:
            log("Vhost Template not provided, not configuring: %s" % port)
            return False
        template_str = config_data[config_key]
    from jinja2 import Template
    template = Template(str(base64.b64decode(template_str)))
    all_items = list(config_data.items()) + list(relationship_data.items())
    template_data = dict(all_items)
    if config_data.get('vhost_template_vars'):
        extra_vars = ast.literal_eval(config_data['vhost_template_vars'])
        template_data.update(extra_vars)
    vhost_name = '%s_%s' % (config_data['servername'], protocol)
    vhost_file = site_filename(vhost_name)
    log("Writing file %s with config and relation data" % vhost_file)
    with open(vhost_file, 'w') as vhost:
        vhost.write(str(template.render(template_data)))
    subprocess.call(['/usr/sbin/a2ensite', vhost_name])
    return True


MPM_TYPES = ['mpm_worker', 'mpm_prefork', 'mpm_event']


def enable_mpm(config):
    """Enables a particular mpm module.

    Different from simply enabling a module, as one and only one mpm module
    *must* be enabled.
    """
    # only do anything if value has changed, to avoid a needless restart
    if not config.changed('mpm_type'):
        return

    mpm_type = config.get('mpm_type', '')
    name = 'mpm_' + mpm_type
    if name not in MPM_TYPES:
        log('bad mpm_type: %s. Falling back to mpm_worker' % mpm_type)
        name = 'mpm_worker'

    # disable all other mpm modules
    for mpm in MPM_TYPES:
        if mpm != name:
            return_value = subprocess.call(['/usr/sbin/a2dismod', mpm])
            if return_value != 0:
                return False

    return_value = subprocess.call(['/usr/sbin/a2enmod', name])
    if return_value != 0:
        return False

    if service_apache2("check"):
        log("Switching mpm module to {}".format(name))
        service_apache2("restart")  # must be a restart to switch mpm
        return True
    else:
        log("Failed to switch mpm module to {}".format(name))
        return False


def config_changed():
    status_set("maintenance", "configuring unit")
    relationship_data = {}
    config_data = config_get()

    apt_source = config_data['apt-source']
    old_apt_source = ''
    try:
        old_apt_source = open('config.apt-source', 'r').read()
    except IOError:
        pass
    if old_apt_source != apt_source:
        subprocess.check_call(['add-apt-repository', '--yes', '-r',
                               old_apt_source])
        add_source(apt_source, config_data['apt-key-id'])
        open('config.apt-source', 'w').write(apt_source)

    ensure_package_status(service_affecting_packages,
                          config_data['package_status'])
    ensure_extra_packages()

    relationship_data.update(get_reverseproxy_data(relation='reverseproxy'))
    relationship_data.update(get_reverseproxy_data(relation='website-cache'))
    if update_balancers():
        # apache 2.4 has lbmethods split, needs to enable specific module(s)
        if is_apache24():
            enable_module('lbmethod_byrequests')

    disabled_modules = config_data['disable_modules'].split()
    apache_websites = ApacheWebsites.from_config(
        relations_of_type("apache-website"), disabled_modules)
    enabled_modules = config_data.get('enable_modules', '').split()
    enabled_modules = apache_websites.list_enabled_modules(enabled_modules)
    for module in enabled_modules:
        enable_module(module)

    if config_data['disable_modules']:
        for module in disabled_modules:
            disable_module(module)

    apache_websites.disable_sites()
    apache_websites.write_configs()
    apache_websites.enable_sites()
    apache_websites.configure_extra_ports()
    all_ports = apache_websites.list_enabled_ports()
    enable_mpm(config_data)
    # XXX we only configure the worker mpm?
    create_mpm_workerfile()
    create_security()

    ports = {'http': 80, 'https': 443}
    for protocol, port in ports.items():
        if create_vhost(
                port,
                protocol=protocol,
                config_key="vhost_%s_template" % protocol,
                config_data=config_data,
                relationship_data=relationship_data):
            all_ports.add(port)

    cert_file = _get_cert_file_location(config_data)
    key_file = _get_key_file_location(config_data)
    chain_file = _get_chain_file_location(config_data)

    if cert_file is not None and key_file is not None:
        # ssl_cert is SELFSIGNED so generate self-signed certificate for use.
        if config_data['ssl_cert'] and config_data['ssl_cert'] == "SELFSIGNED":
            if is_selfsigned_cert_stale(config_data, cert_file, key_file):
                gen_selfsigned_cert(config_data, cert_file, key_file)

        # Use SSL certificate and key provided either as a base64 string or
        # shipped out with the charm.
        else:
            # Certificate provided as base64-encoded string.
            if config_data['ssl_cert']:
                log("Writing cert from config ssl_cert: %s" % cert_file)
                with open(cert_file, 'w') as f:
                    f.write(str(base64.b64decode(config_data['ssl_cert'])))
            # Use certificate file shipped out with charm.
            else:
                source = os.path.join(os.environ['CHARM_DIR'], 'data',
                                      config_data['ssl_certlocation'])
                if os.path.exists(source):
                    shutil.copy(source, cert_file)
                else:
                    log("Certificate not found, ignoring: %s" % source)

            # Private key provided as base64-encoded string.
            if config_data['ssl_key']:
                log("Writing key from config ssl_key: %s" % key_file)
                with open(key_file, 'w') as f:
                    f.write(str(base64.b64decode(config_data['ssl_key'])))
            # Use private key shipped out with charm.
            else:
                source = os.path.join(os.environ['CHARM_DIR'], 'data',
                                      config_data['ssl_keylocation'])
                if os.path.exists(source):
                    shutil.copy(source, key_file)
                else:
                    log("Key file not found, ignoring: %s" % source)

            if chain_file is not None:
                # Chain certificates provided as base64-encoded string.
                if config_data['ssl_chain']:
                    log("Writing chain certificates file from"
                        "config ssl_chain: %s" % chain_file)
                    with open(chain_file, 'w') as f:
                        f.write(str(base64.b64decode(
                            config_data['ssl_chain'])))
                # Use chain certificates shipped out with charm.
                else:
                    source = os.path.join(os.environ['CHARM_DIR'], 'data',
                                          config_data['ssl_chainlocation'])
                    if os.path.exists(source):
                        shutil.copy(source, chain_file)
                    else:
                        log("Chain certificates not found, "
                            "ignoring: %s" % source)

        # Tighten permissions on private key file.
        if os.path.exists(key_file):
            os.chmod(key_file, 0o440)
            os.chown(key_file, pwd.getpwnam('root').pw_uid,
                     grp.getgrnam('ssl-cert').gr_gid)

    apache_syslog_conf = conf_filename("syslog")
    rsyslog_apache_conf = "/etc/rsyslog.d/45-apache2.conf"
    if config_data['use_rsyslog']:
        shutil.copy2("data/syslog-apache.conf", apache_syslog_conf)
        conf_enable("syslog")
        shutil.copy2("data/syslog-rsyslog.conf", rsyslog_apache_conf)
        # Fix permissions of access.log and error.log to allow syslog user to
        # write to
        os.chown("/var/log/apache2/access.log", pwd.getpwnam('syslog').pw_uid,
                 pwd.getpwnam('syslog').pw_gid)
        os.chown("/var/log/apache2/error.log", pwd.getpwnam('syslog').pw_uid,
                 pwd.getpwnam('syslog').pw_gid)
    else:
        conf_disable("syslog")
        if os.path.exists(apache_syslog_conf):
            os.unlink(apache_syslog_conf)
        if os.path.exists(rsyslog_apache_conf):
            os.unlink(rsyslog_apache_conf)
    run(["/usr/sbin/service", "rsyslog", "restart"])

    # Disable the default website because we don't want people to see the
    # "It works!" page on production services and remove the
    # conf.d/other-vhosts-access-log conf.
    ensure_disabled(["000-default"])
    conf_disable("other-vhosts-access-log")
    if os.path.exists(conf_filename("other-vhosts-access-log")):
        os.unlink(conf_filename("other-vhosts-access-log"))

    if service_apache2("check"):
        if config_data["config_change_command"] in ["reload", "restart"]:
            service_apache2(config_data["config_change_command"])
    else:
        status_set("blocked", "service check failed, possible invalid configuration")
        return

    if config_data['openid_provider']:
        if not os.path.exists('/etc/apache2/security'):
            os.mkdir('/etc/apache2/security', 0o755)
        with open('/etc/apache2/security/allowed-ops.txt', 'w') as f:
            f.write(config_data['openid_provider'].replace(',', '\n'))
            f.write('\n')
            os.chmod(key_file, 0o444)

    all_ports.update(update_vhost_config_relation())
    ensure_ports(all_ports)
    update_nrpe_checks()
    ship_logrotate_conf()
    if config_get().changed('servername'):
        logs_relation_joined()

    status_set("active", "Unit is ready")


def ensure_disabled(sites):
    to_disable = [s for s in sites if os.path.exists(site_filename(s, True))]
    if len(to_disable) == 0:
        return
    run(["/usr/sbin/a2dissite"] + to_disable)


def ensure_removed(filename):
    try:
        os.unlink(filename)
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise


class ApacheWebsites:

    @classmethod
    def from_config(cls, relations, disabled_modules):
        """Return an ApacheWebsites with information about all sites."""
        if relations is None:
            relations = []
        self_relations = {}
        for relation in relations:
            self_relation = {'domain': relation.get('domain')}
            enabled = bool(relation.get('enabled', 'False').lower() == 'true')
            site_modules = relation.get('site_modules', '').split()
            for module in site_modules:
                if module in disabled_modules:
                    enabled = False
                    log('site {} requires disabled_module {}'.format(
                        relation['__relid__'], module))
                break
            self_relation['site_modules'] = site_modules
            self_relation['enabled'] = enabled
            self_relation['site_config'] = relation.get('site_config')
            self_relation['ports'] = [
                int(p) for p in relation.get('ports', '').split()]
            self_relations[relation['__relid__']] = self_relation
        return cls(self_relations)

    def __init__(self, relations):
        self.relations = relations

    def write_configs(self):
        for key, relation in self.relations.items():
            config_file = site_filename(key)
            site_config = relation['site_config']
            if site_config is None:
                ensure_removed(config_file)
            else:
                with open(config_file, 'w') as output:
                    output.write(site_config)

    def iter_enabled_sites(self):
        return ((k, v) for k, v in self.relations.items() if v['enabled'])

    def enable_sites(self):
        enabled_sites = [k for k, v in self.iter_enabled_sites()]
        enabled_sites.sort()
        if len(enabled_sites) == 0:
            return
        subprocess.check_call(['/usr/sbin/a2ensite'] + enabled_sites)

    def disable_sites(self):
        disabled_sites = [k for k, v in self.relations.items()
                          if not v['enabled']]
        disabled_sites.sort()
        if len(disabled_sites) == 0:
            return
        ensure_disabled(disabled_sites)

    def list_enabled_modules(self, enabled_modules):
        enabled_modules = set(enabled_modules)
        for key, relation in self.iter_enabled_sites():
            enabled_modules.update(relation['site_modules'])
        return enabled_modules

    def list_enabled_ports(self):
        enabled_ports = set()
        for key, relation in self.iter_enabled_sites():
            enabled_ports.update(relation['ports'])
        return enabled_ports

    def configure_extra_ports(self):
        extra_ports = self.list_enabled_ports()
        extra_ports.discard(80)
        extra_ports.discard(443)
        extra_ports_conf = conf_filename('extra_ports')
        if len(extra_ports) > 0:
            with open(extra_ports_conf, 'w') as f:
                for port in sorted(extra_ports):
                    f.write('Listen {}\n'.format(port))
            conf_enable('extra_ports')
        else:
            conf_disable('extra_ports')
            ensure_removed(extra_ports_conf)


def update_vhost_config_relation():
    """
    Update the vhost file and include the certificate in the relation
    if it is self-signed.
    """
    vhost_ports = set()
    relation_data = relations_of_type("vhost-config")
    config_data = config_get()
    if relation_data is None:
        return vhost_ports

    for unit_data in relation_data:
        if "vhosts" in unit_data:
            all_relation_data = {}
            all_relation_data.update(
                get_reverseproxy_data(relation='reverseproxy'))
            all_relation_data.update(
                get_reverseproxy_data(relation='website-cache'))
            try:
                vhosts = yaml.safe_load(unit_data["vhosts"])
                for vhost in vhosts:
                    port = vhost["port"]
                    if create_vhost(
                            port,
                            template_str=vhost["template"],
                            config_data=config_data,
                            relationship_data=all_relation_data):
                        vhost_ports.add(port)
            except Exception as e:
                log("Error reading configuration data from relation! %s" % e)
                raise

    if service_apache2("check"):
        service_apache2("reload")

    vhost_relation_settings = {
        "servername": config_data["servername"]}

    cert_file = _get_cert_file_location(config_data)
    key_file = _get_key_file_location(config_data)

    if cert_file is not None and key_file is not None:
        if config_data['ssl_cert'] and config_data['ssl_cert'] == "SELFSIGNED":
            with open(cert_file, 'r') as f:
                cert = base64.b64encode(f.read())
            vhost_relation_settings["ssl_cert"] = cert
    for id in relation_ids("vhost-config"):
        relation_set(relation_id=id, relation_settings=vhost_relation_settings)
    return vhost_ports


def start_hook():
    if service_apache2("status"):
        return(service_apache2("restart"))
    else:
        return(service_apache2("start"))


def stop_hook():
    if service_apache2("status"):
        return(service_apache2("stop"))


def reverseproxy_interface(hook_name=None):
    if hook_name is None:
        return(None)
    if hook_name == "changed":
        config_changed()


def website_interface(hook_name=None):
    if hook_name is None:
        return(None)
    my_host = socket.getfqdn(socket.gethostname())
    if my_host == "localhost":
        my_host = socket.gethostname()
    default_port = 80
    subprocess.call([
        'relation-set',
        'port=%d' % default_port,
        'hostname=%s' % my_host,
        'servername=%s' % config_get('servername')
    ])


def ensure_ports(ports):
    """Ensure that only the desired ports are open."""
    open_ports = set(get_open_ports())
    ports = set(ports)
    wanted_closed = ports.difference(open_ports)
    for port in sorted(wanted_closed):
        open_port(port)
    unwanted_open = open_ports.difference(ports)
    for port in sorted(unwanted_open):
        close_port(port)
    set_open_ports(list(sorted(ports)))


def get_open_ports():
    """Get the list of open ports from the standard file."""
    try:
        pfile = open(os.path.join(os.environ['CHARM_DIR'], 'ports.yaml'))
    except IOError as e:
        if e.errno == errno.ENOENT:
            return []
        else:
            raise
    with pfile:
        return yaml.safe_load(pfile)


def set_open_ports(ports):
    """Write the list of open ports to the standard file."""
    ports_path = os.path.join(os.environ['CHARM_DIR'], 'ports.yaml')
    with open(ports_path, 'w') as pfile:
        yaml.safe_dump(ports, pfile)


def get_log_files():
    """
    Read all of the apache config files from __ and get ErrorLog and AccessLog
    values.

    Returns a tuple with first value list of access log files and second value
    list of error log files.
    """
    access_logs = []
    error_logs = []
    for protocol in ['http', 'https']:
        vhost_name = '%s_%s' % (config_get()['servername'], protocol)
        vhost_file = site_filename(vhost_name)
        try:
            # Using read().split('\n') here to work around a mocks open_mock
            # inadequacy: http://bugs.python.org/issue17467
            for line in open(vhost_file, 'r').read().split('\n'):
                if 'CustomLog' in line:
                    access_logs.append(line.split()[1])
                elif 'ErrorLog' in line:
                    error_logs.append(line.split()[1])
        except Exception:
            pass
    return access_logs, error_logs


def logs_relation_joined():
    """
    Sets relation value with filenames
    """
    access_log_files, error_log_files = get_log_files()
    log_files = access_log_files[:]
    log_files.extend(error_log_files)
    types = ['apache_access' for a in access_log_files]
    types.extend(['apache_error' for a in error_log_files])
    data = {'files': '\n'.join(log_files),
            'types': '\n'.join(types),
            }
    _relation_ids = relation_ids('logs')
    for _relation_id in _relation_ids:
        log("logs-relation-joined setting relation data for {} to {}".format(
            _relation_id, data))
        relation_set(
            relation_id=_relation_id,
            relation_settings=data)


###############################################################################
# Main section
###############################################################################
def main(hook_name):
    if hook_name == "install":
        install_hook()
    elif hook_name == "config-changed" or hook_name == "upgrade-charm":
        config_changed()
    elif hook_name == "start":
        start_hook()
    elif hook_name == "stop":
        stop_hook()
    elif hook_name == "reverseproxy-relation-broken":
        config_changed()
    elif hook_name == "reverseproxy-relation-changed":
        config_changed()
    elif hook_name == "reverseproxy-relation-joined":
        config_changed()
    elif hook_name == "balancer-relation-broken":
        config_changed()
    elif hook_name == "balancer-relation-changed":
        config_changed()
    elif hook_name == "balancer-relation-joined":
        config_changed()
    elif hook_name == "website-cache-relation-broken":
        config_changed()
    elif hook_name == "website-cache-relation-changed":
        config_changed()
    elif hook_name == "website-cache-relation-joined":
        config_changed()
    elif hook_name == "website-relation-joined":
        website_interface("joined")
    elif hook_name == 'apache-website-relation-changed':
        config_changed()
    elif hook_name in ("nrpe-external-master-relation-changed",
                       "local-monitors-relation-changed"):
        update_nrpe_checks()
    elif hook_name == "vhost-config-relation-changed":
        config_changed()
    elif hook_name == "logs-relation-joined":
        logs_relation_joined()
    else:
        print("Unknown hook")
        sys.exit(1)


if __name__ == "__main__":
    hook_name = os.path.basename(sys.argv[0])
    # Also support being invoked directly with hook as argument name.
    if hook_name == "hooks.py":
        if len(sys.argv) < 2:
            sys.exit("Missing required hook name argument.")
        hook_name = sys.argv[1]
    main(hook_name)
