__author__ = 'Mattias Lidman'

import unittest
import json
import binascii
import datetime
import time

from collections import namedtuple
from testfixtures import Replacer
from nose.plugins.attrib import attr
from nexus.go_rest_client import GlobusOnlineRestClient
from test_config_file import config

class TestMergedClient(unittest.TestCase):

    def setUp(self):
        self.config = config
        self.replacer = Replacer()
        self.go_rest_client = GlobusOnlineRestClient(config=self.config)

    def tearDown(self):
        self.replacer.restore()

    @attr('integration')
    def test_full_validate_token(self):
        import rsa
        pubkey, privkey = rsa.newkeys(512)
        def get_cert(*args, **kwargs):
            return namedtuple('Request',
                    ['content', 'status_code'])(json.dumps({'pubkey':pubkey.save_pkcs1()}), 200)
        self.replacer.replace('requests.get', get_cert)
        token = 'un=test|client_id=test|SigningSubject=https://graph.api.globusonline.org/goauth/keys/test1|expiry={0}'
        expires = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        token = token.format(time.mktime(expires.timetuple()))
        sig = rsa.sign(token, privkey, 'SHA-1')
        hex_sig = binascii.hexlify(sig)
        token = '{0}|sig={1}'.format(token, hex_sig)
        self.go_rest_client.goauth_validate_token(token)
        sig = sig + 'f'
        hex_sig = binascii.hexlify(sig)
        token = '{0}|sig={1}'.format(token, hex_sig)
        try:
            self.go_rest_client.goauth_validate_token(token)
            self.fail()
        except ValueError:
            pass

    @attr('unit')
    def test_generate_request_url(self):
        expected = "https://" + self.go_rest_client.server + "/goauth/authorize?response_type=code&client_id=testuser1"
        self.assertEqual(expected, self.go_rest_client.goauth_generate_request_url())

    @attr('unit')
    def test_get_access_token(self):
        from nexus.token_utils import DictObj
        expected_expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        expected_expiry = time.mktime(expected_expiry.timetuple())
        result = {
                'access_token': 1234567,
                'refresh_token': 7654321,
                'expires_in': 5 * 60
                }
        def dummy_get_access_token(client_id, client_secret, auth_code, auth_uri ):
            self.assertEqual('my token', auth_code)
            self.assertEqual(self.config['client'], client_id)
            self.assertEqual(self.config['client_secret'], client_secret)
            return DictObj(result) 

        self.replacer.replace('nexus.go_rest_client.token_utils.request_access_token',
            dummy_get_access_token)
        access_token, refresh_token, expiry = self.go_rest_client.goauth_get_access_token_from_code('my token')
        self.assertEqual(1234567, access_token)
        self.assertEqual(7654321, refresh_token)
        self.assertEqual(expected_expiry, expiry)

