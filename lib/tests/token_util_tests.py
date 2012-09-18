import binascii
import datetime
import json
import os
import shutil
import tempfile
import time
import urllib
import unittest
from collections import namedtuple

import requests

import rsa
from rsa import key

from testfixtures import Replacer

from nexus import token_utils

class TestTokenUtils(unittest.TestCase):

    def setUp(self):
        self.replacer = Replacer()

    def tearDown(self):
        self.replacer.restore()

    def test_validate(self):
        expiry = datetime.datetime.utcnow() + datetime.timedelta(seconds=5)
        expiry = int(time.mktime(expiry.timetuple()))
        cert_url = 'http://tester.com/cert1'

        expires = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        unsigned_token = "un=test|clientid=test|expiry={0}|SigningSubject={1}|expiry={2}".format(expiry,
                cert_url, time.mktime(expires.timetuple()))
        unsigned_token = unsigned_token
        pub_key, priv_key = key.newkeys(1024)
        sig = rsa.sign(unsigned_token, priv_key, 'SHA-256')
        tmp_dir = tempfile.mkdtemp()
        os.environ['NEXUS_CACHE_PATH'] = tmp_dir
        encoded_sig = binascii.hexlify(sig)
        signed_token = "{0}|sig={1}".format(unsigned_token,
            encoded_sig)
        response = requests.Response()
        response._content = json.dumps({'pubkey':pub_key.save_pkcs1()})
        def get_cert(*args, **kwargs):
            return namedtuple('Request',
                    ['content', 'status_code'])(json.dumps({'pubkey':pub_key.save_pkcs1()}), 200)
        self.replacer.replace('requests.get', get_cert)

        token_utils.validate_token(signed_token)
        shutil.rmtree(tmp_dir)

    def test_request_access_token(self):
        response = requests.Response()
        response.status_code = requests.codes.created
        access_token = {
                "access_token": "faohwefadfawaw",
                "refresh_token": "fhajhkjbhrafw",
                "expires_in": 123456789,
                "token_type": "Bearer"
                }
        response._content = json.dumps(access_token)
        self.replacer.replace('requests.post', lambda *args, **kwargs: response)
        token_map = token_utils.request_access_token('myid',
                'mysecret','theauthcode', 'http://oauth.org/2/authorize')
        self.assertEqual('faohwefadfawaw', token_map['access_token'])
        self.assertEqual('faohwefadfawaw', token_map.access_token)
        self.assertEqual('fhajhkjbhrafw', token_map['refresh_token'])
        self.assertEqual('fhajhkjbhrafw', token_map.refresh_token)
        self.assertEqual(123456789, token_map['expires_in'])
        self.assertEqual(123456789, token_map.expires_in)
        self.assertEqual('Bearer', token_map['token_type'])
        self.assertEqual('Bearer', token_map.token_type)


    def test_request_access_token_failure(self):
        error_message = {
                    'error_reason': 'authorization not given'
                }
        response = requests.Response()
        response.status_code = requests.codes.conflict
        response._content = json.dumps(error_message)
        self.replacer.replace('requests.post', lambda *args, **kwargs: response)
        call = lambda: token_utils.request_access_token('myid',
                'mysecret','theauthcode', 'http://oauth.org/2/authorize')
        self.assertRaises(token_utils.TokenRequestError, call)


