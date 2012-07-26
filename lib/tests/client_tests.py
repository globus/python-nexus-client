import binascii

from collections import namedtuple
import datetime
import json
import time

import unittest

from nexus import Client

from nose.plugins.attrib import attr

from testfixtures import Replacer

class ClientTests(unittest.TestCase):

    def setUp(self):
        self.config = {
                "authorize_url": "localhost:8080/goauth/authorize",
                "cache": {
                    "class": "nexus.token_utils.InMemoryCache",
                    "args": []
                    },
                "server": "graph.api.globusonline.org",
                "api_key": "I am not a key",
                "api_secret": "I am not a secret", 
                }
        self.replacer = Replacer()

    def tearDown(self):
        self.replacer.restore()

    @attr('unit')
    def test_authenticate_invalid_user(self):
        def error(*args):
            raise ValueError('Invalid Signature')
        self.replacer.replace('nexus.token_utils.validate_token', error)
        client = Client(self.config)
        self.assertFalse(client.authenticate_user('this is a bad token'))

    @attr('unit')
    def test_authenticate_valid_user(self):
        username = 'test1'
        def auth(*args, **kwargs):
            return username
        self.replacer.replace('nexus.token_utils.validate_token', auth)
        client = Client(self.config)
        self.assertEqual(username, client.authenticate_user('this is a good token'))
    
    @attr('integration')
    def test_full_authenticate_user(self):
        import rsa
        pubkey, privkey = rsa.newkeys(512)
        def get_cert(*args, **kwargs):
            return namedtuple('Request',
                    ['content'])(json.dumps({'pubkey':pubkey.save_pkcs1()}))
        self.replacer.replace('requests.get', get_cert)
        token = 'un=test|SigningSubject=https://graph.api.globusonline.org/goauth/keys/test1|expiry={0}'
        expires = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        token = token.format(time.mktime(expires.timetuple()))
        sig = rsa.sign(token, privkey, 'SHA-1')
        hex_sig = binascii.hexlify(sig)
        token = '{0}|sig={1}'.format(token, hex_sig)
        client = Client(self.config)
        self.assertTrue(client.authenticate_user(token))
        sig = sig + 'f'
        hex_sig = binascii.hexlify(sig)
        token = '{0}|sig={1}'.format(token, hex_sig)
        self.assertFalse(client.authenticate_user(token))

    @attr('unit')
    def test_generate_request_url(self):
        client = Client(self.config)
        expected = "https://graph.api.globusonline.org/goauth/authorize?response_type=code&client_id=I+am+not+a+key"
        self.assertEqual(expected, client.generate_request_url())

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
            self.assertEqual(self.config['api_key'], client_id)
            self.assertEqual(self.config['api_secret'], client_secret)
            return DictObj(result) 

        self.replacer.replace('nexus.client.token_utils.request_access_token',
            dummy_get_access_token)
        client = Client(self.config)
        access_token, refresh_token, expiry = client.get_access_token_from_code('my token')
        self.assertEqual(1234567, access_token)
        self.assertEqual(7654321, refresh_token)
        self.assertEqual(expected_expiry, expiry)
