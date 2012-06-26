import binascii

from collections import namedtuple

import unittest

from nexus import Client

from nose.plugins.attrib import attr

from testfixtures import Replacer

class ClientTests(unittest.TestCase):

    def setUp(self):
        self.config = {
                "authorize_url": "localhost:8080/authorize",
                "cache": {
                    "class": "nexus.token_utils.InMemoryCache",
                    "args": []
                    }
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
        def auth(*args, **kwargs):
            return None
        self.replacer.replace('nexus.token_utils.validate_token', auth)
        client = Client(self.config)
        self.assertTrue(client.authenticate_user('this is a good token'))
    
    @attr('integration')
    def test_full_authenticate_user(self):
        import rsa
        pubkey, privkey = rsa.newkeys(512)
        def get_cert(*args, **kwargs):
            return namedtuple('Request', ['content'])(pubkey.save_pkcs1())
        self.replacer.replace('requests.get', get_cert)
        token = 'SigningSubject=https://graph.api.globusonline.org/keys/test1'
        sig = rsa.sign(token, privkey, 'SHA-1')
        hex_sig = binascii.hexlify(sig)
        token = '{0}|sig={1}'.format(token, hex_sig)
        client = Client(self.config)
        self.assertTrue(client.authenticate_user(token))
        sig = sig + 'f'
        hex_sig = binascii.hexlify(sig)
        token = '{0}|sig={1}'.format(token, hex_sig)
        self.assertFalse(client.authenticate_user(token))


