import os.path
import base64
import requests
from getpass import getpass
from nexus import GlobusOnlineRestClient

# This sample makes the following assumptions about the items listed in the
# sample.yml config file:
# 1) 'client' exists as a user on the server and can be authenticated using the
# password 'client_secret'.
# 2) You may authenticate as any user, as long as the user has registered the
# public part of whatever private key is listed as the 'user_private_key_file'.
# By default the dummy_key in this sample directory is used, so the dummy_key.pub
# must be registered with the users account.

# First instantiate a client object either with a dictionary or with a yaml file
pwd = os.path.dirname(__file__)
user_client = GlobusOnlineRestClient(config_file=os.path.join(pwd, 'user_client_config.yml'))
alias_client = GlobusOnlineRestClient(config_file=os.path.join(pwd, 'alias_client_config.yml'))

# Add the rsa key from the file specified in alias_client_config.yml
# to the alias_client's list of rsa keys
filename = alias_client.user_key_file+".pub"
print "Adding rsa key from " + filename
response, content = alias_client.post_rsa_key('test', rsa_key_file=filename)
if response['status'] == '201':
    print "key successfully added"
elif response['status'] == '409':
    print "key already exists on user's key list"
else:
    print "unable to add key"


# Fetch an Access Token via a basic auth header
print("Getting an Access Token via a Client Credentials OAuth flow.")
token_url = 'https://nexus.api.globusonline.org/goauth/token?grant_type=client_credentials'
username = raw_input("Please enter your Nexus username: ")
password = getpass("Please enter your Nexus password: ")

auth_header = 'Basic {}'.format(
    base64.b64encode('{0}:{1}'.format(username, password)))
response = requests.post(token_url, headers={'Authorization': auth_header})
access_token = response.json()['access_token']

# make sure it's a good token
print("Validate access token:")
alias, client_id, nexus_host = user_client.goauth_validate_token(access_token)
print(nexus_host + " claims this is a valid token issued by " + alias + " for " + client_id)

print("Use access token to act as " + alias + ":")
response = user_client.goauth_get_user_using_access_token(access_token)
print response
