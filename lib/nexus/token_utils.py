"""
Utilities for working with nexus tokens.

Helps with generating tokens, validating tokens.
"""
import binascii
import hashlib
import os
import re
import urllib

import requests
import rsa

class InMemoryCache(object):

    def __init__(self):
        self.cache_map = {}

    def save_public_key(self, key_id, key):
        self.cache_map[key_id] = key

    def has_public_key(self, key_id):
        return key_id in self.cache_map

    def get_public_key(self, key_id):
        return rsa.PublicKey.load_pkcs1(self.cache_map[key_id])

class FileSystemCache(object):

    def __init__(self, cache_path):
        self.cache_path = cache_path
        if not os.path.exists(self.cache_path):
            os.makedirs(self.cache_path)

    def save_public_key(self, key_id, key):
        cached_cert_path = os.path.join(self.cache_path,
            "{0}.pem".format(key_id))
        with open(cached_cert_path, 'w') as cert:
            cert.write(str(key))

    def has_public_key(self, key_id):
        cached_cert_path = os.path.join(self.cache_path,
            "{0}.pem".format(key_id))
        return os.path.exists(cached_cert_path)

    def get_public_key(self, key_id):
        cached_cert_path = os.path.join(self.cache_path,
            "{0}.pem".format(key_id))
        with open(cached_cert_path, 'r') as cert:
            return rsa.PublicKey.load_pkcs1(cert.read())


def validate_token(token, cache=InMemoryCache()):
    """
    Given a token validate it.

    Keyword arguments:
    :param tokens: A signed authentication token which was provided by Nexus

    :raises ValueError: If the signature is invalid
    """
    unencoded_token = urllib.unquote(token)
    token_map = {}
    for entry in unencoded_token.split('|'):
        key, value = entry.split('=')
        token_map[key] = value
    subject_hash = hashlib.md5(token_map['SigningSubject']).hexdigest()
    if not cache.has_public_key(subject_hash):
        public_key = requests.get(token_map['SigningSubject']).content
        cache.save_public_key(subject_hash, public_key)
    public_key = cache.get_public_key(subject_hash)
    sig = token_map.pop('sig')
    match = re.match('^(.+)\|sig=.*', unencoded_token)
    signed_data = match.group(1)
    try:
        sig = binascii.a2b_hex(sig)
        rsa.verify(signed_data, sig, public_key)
    except rsa.VerificationError:
        raise ValueError('Invalid Signature')


def request_access_token(client_id, client_secret, auth_code, auth_uri):
    """
    Given an authorization code, request an access token.

    :param client_id: The client's api id
    :param client_secret: The client's api secret
    :param auth_code: The authorization code given to the resource owner by nexus
    :param auth_uri: The url of the authentication endpoint

    :returns: A dictionary of the access code response.  This will include the
    fields: access_token, refresh_token and expires_in

    :raises AccessTokenRequestError: If the request for an access token fails
    """
    payload = {
            'grant_type': 'authorization_code',
            'code': auth_code,
            }
    response = requests.post(auth_uri,
            auth=(client_id, client_secret),
            data=payload, verify=True)
    if response.status_code == requests.codes.ok:
        return response.json
    raise TokenRequestError(response.json)

def get_token_refresh(self, client_id, client_secret, refresh_token, auth_uri):
    payload = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            }
    response = requests.post(auth_uri,
            auth=(client_id, client_secret),
            data=payload, verify=True)
    if response.status_code == requests.codes.ok:
        return response.json
    raise TokenRequestError(response.json)


class TokenRequestError(Exception):
    """
    Just an Error class that takes a json response as a property.
    """

    def __init__(self, error):
        super(TokenRequestError, self).__init__()
        self.error = error





