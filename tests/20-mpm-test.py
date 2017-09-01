#!/usr/bin/env python3
import os
import time
import unittest
import amulet

seconds_to_wait = 600


class BundleTest(unittest.TestCase):
    """ Create a class for testing the charm in the unit test framework. """
    @classmethod
    def setUpClass(cls):
        """ Set up an amulet deployment using the bundle. """
        d = amulet.Deployment(series='trusty')
        d.add('apache2', os.path.join(os.path.dirname(__file__), os.pardir))
        d.setup(timeout=seconds_to_wait)
        d.sentry.wait(timeout=seconds_to_wait)
        cls.d = d
        cls.unit = d.sentry['apache2'][0]
        output, code = cls.unit.run('curl localhost')

    def assert_mpm(self, mpm):
        cmd = (". /etc/apache2/envvars && apache2 -V 2>/dev/null "
               "| grep MPM | awk -F: '{print $2}' | xargs")
        self.d.configure('apache2', {'mpm_type': mpm})
        self.d.sentry.wait()
        # the above doesn't seem to work
        time.sleep(10)
        # enable default web site so we can check for a valid config
        output, code = self.unit.run(
            'a2ensite 000-default.conf && service apache2 reload')
        time.sleep(10)
        # enable default web site so we can check for a valid config
        output, code = self.unit.run(cmd)
        self.assertEqual(code, 0)
        self.assertIn(mpm, output)
        output, code = self.unit.run('curl localhost')
        if code != 0:
            raise Exception(output)
        self.assertEqual(code, 0)

    def test_mpm_worker(self):
        self.assert_mpm('worker')

    def test_mpm_prefork(self):
        self.assert_mpm('prefork')

    def test_mpm_event(self):
        self.assert_mpm('event')


if __name__ == '__main__':
    unittest.main()
