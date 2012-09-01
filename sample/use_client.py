import os.path
from getpass import getpass
from nexus import Client

# First instantiate a client object either with a dictionary or with a yaml file
pwd = os.path.dirname(__file__)
client = Client(config_file=os.path.join(pwd, 'sample.yml'))
# Generate a url for the end user to use to authorize this client/authenticate.
url = client.generate_request_url()
print "Please authenticate using the following url"
print url
token = raw_input("Please copy the resulting code here: ")
# At this point the end user needs to authenticate with the supplied url.  The
# easiest way to do this is: curl -k --user test:test1 "<supplied_url>".  The
# result will contain the token in the "code" field.  Paste that here.

# Validate the token:
try:
    user, clientid, nexus_host = client.validate_token(token)
    print "Yup, you are {0}".format(user)
except:
    print "That is not a valid authorization code"

print("As " + user + ", get an access key for yourself using rsa:")
print client.request_client_credential(user, lambda: getpass("Private Key Password"))

print("As " + user + ", get a request token for client " + client.client + " using rsa authentication:")
response = client.rsa_get_request_token(user, client.client, lambda: getpass("Private Key Password"))
print response

print("As " + client.client + ", get an access key from code:")
access_token, refresh_token, expires_in = client.get_access_token_from_code(response['code'])
print access_token

print("Validate access token:")
user, clientid, nexus_host = client.validate_token(access_token)
print(nexus_host + " claims this is a valid token issued by " + user + " for " + clientid)

print("Use access token to act as " + user + ":")
response = client.get_user_using_access_token(access_token)
print response
