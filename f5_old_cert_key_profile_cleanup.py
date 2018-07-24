#!/usr/bin/python
# f5_old_cert_key_profile_cleanup.py
# Author: Chad Jenison (c.jenison at f5.com)
# Version 1.0
#
# Script that uses F5 BIG-IP iControl REST API to display cert and expiration information on a virtual server basis

import argparse
import sys
import requests
import json
import getpass
from datetime import datetime

#Setup command line arguments using Python argparse
parser = argparse.ArgumentParser(description='A tool to display virtual server certificate information')
parser.add_argument('--bigip', help='IP or hostname of BIG-IP Management or Self IP', required=True)
parser.add_argument('--user', help='username to use for authentication', required=True)

args = parser.parse_args()
contentJsonHeader = {'Content-Type': "application/json"}



def get_auth_token(bigip, username, password):
    authbip = requests.session()
    authbip.verify = False
    payload = {}
    payload['username'] = username
    payload['password'] = password
    payload['loginProviderName'] = 'tmos'
    authurl = 'https://%s/mgmt/shared/authn/login' % (bigip)
    authPost = authbip.post(authurl, headers=contentJsonHeader, data=json.dumps(payload))
    if authPost.status_code == 404:
        print ('attempt to obtain authentication token failed; will fall back to basic authentication; remote LDAP auth will require configuration of local user account')
        token = None
    elif authPost.status_code == 401:
        print ('attempt to obtain authentication token failed due to invalid credentials')
        token = 'Fail'
    elif authPost.json().get('token'):
        token = authPost.json()['token']['token']
        print ('Got Auth Token: %s' % (token))
    else:
        print ('Unexpected error attempting POST to get auth token')
        jquit()
    return token

user = args.user
password = getpass.getpass("Password for " + user + ":")
bip = requests.session()
token = get_auth_token(args.bigip, args.user, password)
if token and token != 'Fail':
    bip.headers.update({'X-F5-Auth-Token': token})
else:
    bip.auth = (username, password)
bip.verify = False
requests.packages.urllib3.disable_warnings()
url_base = ('https://%s/mgmt/tm' % (args.bigip))


factoryclientsslprofiles = set(['/Common/clientssl', '/Common/clientssl-insecure-compatible', '/Common/clientssl-secure', '/Common/crypto-server-default-clientssl', '/Common/splitsession-default-clientssl', '/Common/wom-default-clientssl'])
factorycerts = set(['/Common/ca-bundle.crt', '/Common/default.crt', '/Common/f5-ca-bundle.crt', '/Common/f5-irule.crt'])
factorykeys = set(['/Common/default.key', '/Common/f5_api_com.key'])
clientsslprofiles = set()
usedclientsslprofiles = set()
expiredcertclientsslprofiles = set()
certs = set()
keys = set()
expiredcerts = set()
soontoexpirecerts = set()
usedcerts = set()
usedkeys = set()
virtualsWithExpiredCerts = set()

retrievedclientsslprofiles = bip.get('%s/ltm/profile/client-ssl' % (url_base)).json()
for clientssl in retrievedclientsslprofiles['items']:
    clientsslprofiles.add(clientssl['fullPath'])

retrievedcerts = bip.get('%s/sys/file/ssl-cert/' % (url_base)).json()
for cert in retrievedcerts['items']:
    certs.add(cert['fullPath'])
    certinfo = bip.get('%s/sys/file/ssl-cert/%s' % (url_base, cert['fullPath'].replace("/", "~", 2))).json()
    utcinseconds = (datetime.utcnow() - datetime(1970,1,1)).total_seconds()
    if certinfo['expirationDate'] - utcinseconds < 7776000:
        if certinfo['expirationDate'] < utcinseconds:
            expiredcerts.add(cert['fullPath'])
        else:
            soontoexpirecerts.add(cert['fullPath'])

retreivedkeys = bip.get('%s/sys/file/ssl-key/' % (url_base)).json()
for key in retreivedkeys['items']:
    keys.add(key['fullPath'])

def processClientSslProfileFromVirtual(profileFullPath):
    clientsslprofile = bip.get('%s/ltm/profile/client-ssl/%s' % (url_base, profileFullPath.replace("/", "~", 2))).json()
    usedclientsslprofiles.add(profileFullPath)
    # insert code for defaultsFrom (parent) handling
    if clientsslprofile.get('defaultsFrom'):
        if clientsslprofile['defaultsFrom'] != '/Common/clientssl' and clientsslprofile['defaultsFrom'] != 'none':
            processClientSslProfile(clientsslprofile['defaultsFrom'])
    if (clientsslprofile['cert'] in expiredcerts):
        expiredcertclientsslprofiles.add(profileFullPath)
    if clientsslprofile['chain'] != 'none':
        usedcerts.add(clientsslprofile['chain'])
    usedcerts.add(clientsslprofile['cert'])
    usedkeys.add(clientsslprofile['key'])

virtuals = bip.get('%s/ltm/virtual' % (url_base)).json()
for virtual in virtuals['items']:
    #print ('Virtual: %s' % (virtual['fullPath']))
    virtualprofiles = bip.get('%s/ltm/virtual/%s/profiles' % (url_base, virtual['fullPath'].replace("/", "~", 2))).json()
    if virtualprofiles.get('items'):
        for profile in virtualprofiles['items']:
            if profile['fullPath'] in clientsslprofiles:
                processClientSslProfileFromVirtual(profile['fullPath'])

unusedclientsslprofiles = clientsslprofiles - usedclientsslprofiles
unusedcerts = certs - usedcerts
unusedkeys = keys - usedkeys

print ('Usedclientsslprofiles: %s' % (usedclientsslprofiles))
print ('Usedcerts: %s' % (usedcerts))
print ('Unusedcerts: %s' % (unusedcerts))
print ('Usedkeys: %s' % (usedkeys))
print ('Unusedkeys: %s' % (unusedkeys))
