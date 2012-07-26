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
user = client.authenticate_user(token)
if user is not None:
    print "Yup, you are {0}".format(user)
else:
    print "That is not a valid authorization code"


#Get an access key for yourself using rsa:
print client.request_client_credential(user, lambda: getpass("Private Key Password"))

print "Get a request token using rsa authentication"
print client.rsa_get_request_token(user, lambda: getpass("Private Key Password"))
