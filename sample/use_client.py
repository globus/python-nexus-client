import os.path
from getpass import getpass
from nexus import GlobusOnlineRestClient

# This sample makes the following assumptions about the items listed in the
# sample.yml config file:
# 1) 'client' exists as a user on the server and can be authenticated using the
# password 'password'.
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

# Generate a url for the end user to use to authorize this client/authenticate.
url = alias_client.goauth_generate_request_url()
print "Please authenticate using the following url"
print url
token = raw_input("Please copy the resulting code here: ")
# At this point the end user needs to authenticate with the supplied url.  The
# easiest way to do this is: curl -k --user test:test1 "<supplied_url>".  The
# result will contain the token in the "code" field.  Paste that here.

# Validate the token:
try:
    alias, client_id, nexus_host = alias_client.goauth_validate_token(token)
    print "Yup, you are {0}".format(alias)
except:
    print "That is not a valid authorization code"

print("As " + alias + ", get an access key for yourself using rsa:")
print alias_client.goauth_request_client_credential(alias, lambda: getpass("Private Key Password"))

print("As " + alias + ", get a request token for client " + user_client.client + " using rsa authentication:")
response, content = alias_client.goauth_rsa_get_request_token(alias, user_client.client, lambda: getpass("Private Key Password"))
print content

print("As " + user_client.client + ", get an access key from code:")
access_token, refresh_token, expires_in = user_client.goauth_get_access_token_from_code(content['code'])
print access_token

print("Validate access token:")
alias, client_id, nexus_host = user_client.goauth_validate_token(access_token)
print(nexus_host + " claims this is a valid token issued by " + alias + " for " + client_id)

print("Use access token to act as " + alias + ":")
response = user_client.goauth_get_user_using_access_token(access_token)
print response
