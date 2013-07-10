import os.path
from getpass import getpass
from nexus import GlobusOnlineRestClient


# First instantiate a client object either with a dictionary or with a yaml file
pwd = os.path.dirname(__file__)
client = GlobusOnlineRestClient(config_file=os.path.join(pwd, 'client_config.yml'))

# get and access token
print 'Get an access token with a username and rsa key: '
user = raw_input('username: ')
response = client.goauth_request_client_credential(user, lambda: getpass("Private Key Password: "))
access_token = response['access_token']

# try to login with the access token
print 'Login with the access token: '
client.username_goauth_token_login(user, access_token)
if(user == client.current_user):
    print 'successful login as ' + user
else:
    print 'login failed'
