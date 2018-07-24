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

# Taken from http://code.activestate.com/recipes/577058/
def query_yes_no(question, default="no"):
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    if default == None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)
    while 1:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid.keys():
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")

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
        quit()
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
soontoexpirecertclientsslprofiles = set()
certs = set()
keys = set()
expiredcerts = set()
soontoexpirecerts = set()
usedcerts = set()
usedkeys = set()
virtualsWithExpiredCerts = set()
virtualsWithSoonToExpireCerts = set()


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

retrievedclientsslprofiles = bip.get('%s/ltm/profile/client-ssl' % (url_base)).json()
for clientssl in retrievedclientsslprofiles['items']:
    clientsslprofiles.add(clientssl['fullPath'])
    clientsslprofile = bip.get('%s/ltm/profile/client-ssl/%s' % (url_base, clientssl['fullPath'].replace("/", "~", 2))).json()
    if clientsslprofile['cert'] in expiredcerts:
        expiredcertclientsslprofiles.add(clientssl['fullPath'])
    if clientsslprofile['cert'] in soontoexpirecerts:
        soontoexpirecertclientsslprofiles.add(clientssl['fullPath'])

def processClientSslProfileFromVirtual(profileFullPath):
    clientsslprofile = bip.get('%s/ltm/profile/client-ssl/%s' % (url_base, profileFullPath.replace("/", "~", 2))).json()
    usedclientsslprofiles.add(profileFullPath)
    # insert code for defaultsFrom (parent) handling
    if clientsslprofile.get('defaultsFrom'):
        if clientsslprofile['defaultsFrom'] != '/Common/clientssl' and clientsslprofile['defaultsFrom'] != 'none':
            processClientSslProfile(clientsslprofile['defaultsFrom'])
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
                if profile['fullPath'] in expiredcertclientsslprofiles:
                    virtualsWithExpiredCerts.add(virtual['fullPath'])
                if profile['fullPath'] in soontoexpirecertclientsslprofiles:
                    virtualsWithSoonToExpireCerts.add(virtual['fullPath'])

unusedclientsslprofiles = clientsslprofiles - usedclientsslprofiles
unusedcerts = certs - usedcerts
unusedkeys = keys - usedkeys

#for clientsslprofile in expiredcertclientsslprofiles:
#    print('Client-ssl profile: %s uses an expired cert' % (clientsslprofile))

for clientsslprofile in expiredcertclientsslprofiles:
    if clientsslprofile in unusedclientsslprofiles:
        if clientsslprofile not in factoryclientsslprofiles:
            queryString = 'Client-ssl profile: %s is not used by a virtual server and has an expired cert; Delete profile?' % (clientsslprofile)
            if query_yes_no(queryString, default='no'):
                profile = bip.get('%s/ltm/profile/client-ssl/%s' % (url_base, clientsslprofile.replace("/", "~", 2))).json()
                deleteprofile = bip.delete('%s/ltm/profile/client-ssl/%s' % (url_base, clientsslprofile.replace("/", "~", 2)))
                if deleteprofile.status_code == 200:
                    print('Successfully deleted client-ssl profile %s' % (clientsslprofile))
                    #print('cert: %s - usedcerts: %s' % (profile['cert'], usedcerts))
                    if profile['cert'] not in usedcerts and profile['cert'] not in factorycerts:
                        queryString = 'Cert: %s from deleted client-ssl profile: %s not used; delete it?' % (profile['cert'], clientsslprofile)
                        if query_yes_no(queryString, default='no'):
                            deletecert = bip.delete('%s/sys/file/ssl-cert/%s' % (url_base, profile['cert'].replace("/", "~", 2)))
                            if deletecert.status_code == 200:
                                print('Successfully deleted cert %s' % (profile['cert']))
                                expiredcerts.discard(profile['cert'])
                            else:
                                print('Unable to delete cert %s' % (profile['cert']))
                                print('Message: %s' % (deletecert.json()['message']))
                    if profile['key'] not in usedkeys and profile['key'] not in factorykeys:
                        queryString = 'Key: %s from deleted client-ssl profile: %s not used; delete it?' % (profile['key'], clientsslprofile)
                        if query_yes_no(queryString, default='no'):
                            deletekey = bip.delete('%s/sys/file/ssl-key/%s' % (url_base, profile['key'].replace("/", "~", 2)))
                            if deletekey.status_code == 200:
                                print('Successfully deleted key %s' % (profile['key']))
                            else:
                                print('Unable to delete key %s' % (profile['key']))
                                print('Message: %s' % (deletekey.json()['message']))
                else:
                    print('Unable to delete client-ssl profile %s' % (clientsslprofile))
                    print('Message: %s' % (deleteprofile.json()['message']))

for virtual in virtualsWithExpiredCerts:
    print('Virtual: %s is using a client-ssl profile with an expired cert' % (virtual))
for virtual in virtualsWithSoonToExpireCerts:
    print('Virtual: %s is using a client-ssl profile with a soon to expire cert' % (virtual))
for clientsslprofile in soontoexpirecertclientsslprofiles:
    print('Client-ssl profile: %s is using a soon to expire cert' % (clientsslprofile))
for cert in expiredcerts:
    print('Cert: %s is expired' % (cert))
for cert in soontoexpirecerts:
    print('Cert: %s is expiring soon' % (cert))

#print ('Usedclientsslprofiles: %s' % (usedclientsslprofiles))
#print ('Expiredclientsslprofiles: %s' % (expiredcertclientsslprofiles))
#print ('Usedcerts: %s' % (usedcerts))
#print ('Unusedcerts: %s' % (unusedcerts))
#print ('Usedkeys: %s' % (usedkeys))
#print ('Unusedkeys: %s' % (unusedkeys))
