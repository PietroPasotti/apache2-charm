# Juju charm for Apache

The Apache Software Foundation's goal is to build a secure,
efficient and extensible HTTP server as standards-compliant open
source software. The result has long been the number one web server
on the Internet.  It features support for HTTPS, virtual hosting,
CGI, SSI, IPv6, easy scripting and database integration,
request/response filtering, many flexible authentication schemes,
and more.

## How to deploy the charm

    juju deploy apache2
    juju config apache2 "vhost_http_template=$(base64 < http_vhost.tmpl)"

    # and / or
    juju config apache2 "vhost_https_template=$(base64 < https_vhost.tmpl)"

If you want a simple `reverseproxy` relation to your services (only
really useful if you have a single unit on the other side of the
relation):

    juju relate apache2:reverseproxy haproxy:website
    # and / or
    juju relate apache2:reverseproxy squid-reverseproxy:cached-website

Alternatively, you can use the `balancer` relation so that requests
are load balanced across multiple units of your services. For more information see the section on `Using the balancer relation`:

    juju relate apache2:balancer haproxy:website
    # and / or
    juju relate apache2:balancer squid-reverseproxy:cached-website

## VirtualHost templates

The charm expects a jinja2 template to be passed in. The variables
in the template should relate to the services that apache will be
proxying -- obviously no variables need to be specified if no
proxying is needed.

Virtual host templates can also be specified via relation.  See the
vhost-config relation section below for more information.

The vhost_template_vars config allows for further customisation of the vhost
templates. For example, you can have a single template for a particular
service, but use vhost_template_vars to customise it slightly for
devel/staging/production environments.

### Using the reverseproxy relation

The charm will create the service variable, with the `unit_name`,
when the `reverseproxy` relationship is joined and present this to
the template at which point the vhost will be generated from the
template again.  All config settings are also available to the
template.

For example to access squid then the `{{ squid }}` variable should
be used.  This will be populated with the hostname:port of the squid
service. The individual hostname and port can also be accessed via
`squid_hostname` and `squid_port`.

Note: The service name should be used, not the charm name.  If
      deploying a charm with a different service name, use that
      instead.

The joining charm may set an `all_services` variable which
contains a list of services it provides in yaml format (list of
associative arrays):

    # ... in haproxy charm, website-relation-joined
    relation-set all_services="
      - {service_name: gunicorn, service_port: 80}
      - {service_name: solr, service_port: 8080}
      - {service_name: my-webapp, service_port: 9090}
    "

then variables for each service would be available to the jinja2
template in `<juju_service_name>_<sub_service_name>`.  In our example
above haproxy contains stanzas named gunicorn, solr and my-webapp.
These are accessed as `{{ haproxy_gunicorn }}`, `{{ haproxy_solr }}` and
`{{ haproxy_mywebapp }}` respectively.  If any unsupported characters
are in your juju service name or the service names exposed through
"all_services", they will be stripped.

For example a vhost that will pass all traffic on to an haproxy instance:

    <VirtualHost *:80>
        ServerName radiotiptop.org.uk

        CustomLog /var/log/apache2/radiotiptop-access.log combined
        ErrorLog /var/log/apache2/radiotiptop-error.log

        DocumentRoot /srv/radiotiptop/www/root

        ProxyRequests off
        <Proxy *>
            Order Allow,Deny
            Allow from All
            ErrorDocument 403 /offline.html
            ErrorDocument 500 /offline.html
            ErrorDocument 502 /offline.html
            ErrorDocument 503 /offline.html
        </Proxy>

        ProxyPreserveHost off
        ProxyPassReverse / http://{{ haproxy_gunicorn }}/

        RewriteEngine on

        RewriteRule ^/$ /index.html [L]
        RewriteRule ^/(.*)$ http://{{ haproxy_gunicorn }}/$1 [P,L]
    </VirtualHost>

### Using the `balancer` relation

Using the balancer relation will set up named balancers using
Apache's mod_balancer. Each balancer will be named after the
`sitenames` or `all_services` setting exported from the other side
of the relation. Requests sent through those balancers will have a
`X-Balancer-Name` header set, which can be used by the related
service to appropriatedly route requests internally.

The joining charm may set an `all_services` variable which
contains a list of services it provides in yaml format (list of
associative arrays):

    # ... in haproxy charm, website-relation-joined
    relation-set all_services="
      - {service_name: gunicorn, service_port: 80}
      - {service_name: solr, service_port: 8080}
      - {service_name: my-webapp, service_port: 9090}
    "

Each separate service name will cause a new `balancer` definition to be created on the Apache side, like:

  <Proxy balancer://gunicorn>
    ProxySet lbmethod=byrequests
    RequestHeader set X-Balancer-Name "gunicorn"
  </Proxy>

For example a vhost that will pass specific requests to the `gunicorn` service that's defined in haproxy:

    <VirtualHost *:80>
        ServerName radiotiptop.org.uk

        CustomLog /var/log/apache2/radiotiptop-access.log combined
        ErrorLog /var/log/apache2/radiotiptop-error.log

        DocumentRoot /srv/radiotiptop/www/root

        ProxyRequests off
        <Proxy *>
            Order Allow,Deny
            Allow from All
            ErrorDocument 403 /offline.html
            ErrorDocument 500 /offline.html
            ErrorDocument 502 /offline.html
            ErrorDocument 503 /offline.html
        </Proxy>

        ProxyPreserveHost on

        RewriteEngine on

        RewriteRule ^/$ /index.html [L]
        RewriteRule ^/(.*)$ balancer://gunicorn/$1 [P,L]
    </VirtualHost>

### Using the vhost-config relation

The nice thing about this relation, is as long as a charm support it, deploying
apache as a front-end for a web service should be as simple as establishing the
relation.  If you need more details for how to implement this, read on.

The template files themselves can be specified via this relation.  This makes
deployment of your infrastructure simpler, since users no longer need to
specify a vhosts config option when using apache2 (though they still can).  A
candidate charm should provide a relation on the `apache-vhost-config`
interface.  This charm should simply set the following data when relating:

    relation-set vhosts="- {port: '443', template: dGVtcGxhdGU=}\n- {port: '80', template: dGVtcGxhdGU=}\n"

Notice the `vhosts` definition is in yaml, the format is simple. `vhosts`
should contain a yaml encoded data structure of a list of key value hashes, or
dictionaries.  In each dictionary, `port` should be set to the port this vhost
should listen on, `template` should be set to the base64 encoded template file.
You can include as many of these dictionaries as you would like.  If you have
colliding port numbers across your juju infrastructure, the results will be a
bit unpredictable.

For example, if using python for your relating charm, the code to generate a
yaml_string for a vhost on port `80` would be similar to this:

    import yaml
    import base64
    template = get_template()
    vhosts = [{"port": "80", "template": base64.b64encode(template)}]
    yaml_string = yaml.dump(vhosts)

Note, that if you are opening a non-standard port (80 and 443 are opened and
understood by the default install of apache2 in Ubuntu) you will need to
instruct Apache to `Listen` on that port in your vhost file.  Something like the
following will work in your vhost template:

    Listen 8080
    <VirtualHost *:8080>
    ...
    </VirtualHost>


#### Relation settings that apache2 provides

When your charm relates it will be provided with the following:

 * `servername` - The Apache2 servername.  This is typically needed by web
   applications so they know how to write URLs.

 * `ssl_cert` - If you asked for a selfsigned certificate, that cert will
   be available in this setting as a base64 encoded string.


### Using the apache-website relation

The apache-website relation provides a very flexible way of configuring an
Apache2 website, using subordinate charms.  It can support reverse proxies,
static websites, and probably many other forms.

To support this relation, a charm must set

 * `domain` - The fully-qualified domain name of the site.

 * `enabled` - Must be set to 'true' when the web site is ready to be used.

 * `site_config` - A vhost configuration block.

 * `site_modules` - A list of modules required by the site.  If any of these
   appear in `disable_modules`, the site will not be enabled.  Otherwise, any
   required modules will be loaded.

 * `ports` - A space-separated list of ports that the site uses.

### Using the logs relation

The logs relation is for use with a logging subordinate charm. The beaver
subordinate can be deployed and related to apache and logstash. Beaver will
tail apache logs and send the logs to logstash.

## Certs, keys and chains

`ssl_keylocation`, `ssl_certlocation` and `ssl_chainlocation` are
file names in the charm `/data` directory.  If found, they will be
copied as follows:

  - /etc/ssl/private/<ssl_keylocation>
  - /etc/ssl/certs/<ssl_certlocation>
  - /etc/ssl/certs/<ssl_chainlocation>

`ssl_key` and `ssl_cert` can also be specified which are are assumed
to be base64 encoded.  If specified, they will be written to
appropriate directories given the values in ssl_keylocation and
ssl_certlocation as listed above.

`ssl_cert` may also be set to SELFSIGNED, which will generate a
certificate.  This, of course, is mostly useful for testing and
staging purposes.  The generated certifcate/key will be placed
according to `ssl_certlocation` and `ssl_keylocation` as listed
above.

`ssl_protocol`, `ssl_honor_cipher_order`, and `ssl_cipher_suite` can
be used to override SSL/TLS version and the cipher suites supported.
These default to what Canonical IS recommends and is using. Before
making any changes, please see the Mozilla Security/Server Side TLS.

## `{enable,disable}_modules`

Space separated list of modules to be enabled or disabled. If a module to
be enabled cannot be found then the charm will attempt to install it.

## OpenId 

The openid_provider option takes a comma seperated list of OpenID
providers and places them in /etc/apache2/security/allowed-ops.txt. That
file can then be refernced by the allowed-op-list-url option when using
apache_openid

## TODO:

  * Document the use of balancer, nrpe, logging and website-cache

  * Method to deliver site content. This maybe by converting the
    charm to a subordinate and making it the master charms problem

  * Implement secure method for delivering key.  Juju will likely
    need to provide this.

  * Tuning. No tuning options are present. Convert apache2.conf to a
    template and expose config options

  * The `all_services` variable can be passed as part of the http interface and is
    optional. However its kind of secret and it would be more obvious if a
    separate interface was used like http-allservices.

## Development

The following steps are needed for testing and development of the
charm, but **not** for deployment:

    sudo apt-get install python-software-properties
    sudo add-apt-repository ppa:chrisjohnston/flake8
    sudo apt-get update
    sudo apt-get install python-flake8 python-nose python-coverage \
                         python-testtools python-pyasn1 python-pyasn1-modules

To fetch additional source dependencies and run the tests:

    make build

... will run the unit tests, run flake8 over the source to warn
about formatting issues and output a code coverage summary of the
'hooks.py' module.
