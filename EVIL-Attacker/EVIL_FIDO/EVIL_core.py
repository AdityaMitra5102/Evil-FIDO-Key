import os
import uuid
import cbor2

file_path="keys.secret"

current_keys={}

while True:
    print("Reading crypto file")
    try:
        if not os.path.exists(file_path):
            empty_keys={}
            with open(file_path,'wb') as file:
                x=cbor2.dumps(empty_keys)
                file.write(x)


        with open(file_path,'rb') as file:
            cbin=file.read()
            current_keys=cbor2.loads(cbin)

        break
    except:
        pass

print('Keys loaded')

def reload_keys():
    global current_keys
    while True:
        print("Reading crypto file")
        try:
            if not os.path.exists(file_path):
                empty_keys={}
                with open(file_path,'wb') as file:
                    x=cbor2.dumps(empty_keys)
                    file.write(x)


            with open(file_path,'rb') as file:
                cbin=file.read()
                current_keys=cbor2.loads(cbin)

            break
        except:
            pass

   
def check_key_exists(rpid, cred_id):
    return rpid in current_keys and cred_id in current_keys[rpid]

def check_key_entity_exists(rpid, entity):
    return check_key_exists(rpid, entity['id'])

def get_key(rpid, cred_id):
    if not check_key_exists(rpid, cred_id):
        return None
    return current_keys[rpid][cred_id]

def get_all_keys(rpid):
    if rpid in current_keys:
        return current_keys[rpid]
    return None
    
def get_cred_entity(rpid, cred_id):
    if not check_key_exists(rpid, cred_id):
        return None
    return current_keys[rpid][cred_id]['publickeyentity']

############################### Cryptographic Operations ######################
from hashlib import sha256
from ecdsa import SigningKey, VerifyingKey, NIST256p
from cryptography import x509 
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.backends import default_backend
import datetime



def genCryptoKeys(secret_string):
    hash_of_secret = sha256(secret_string.encode()).digest()
    private_key = SigningKey.from_string(hash_of_secret[:32], curve=NIST256p)
    public_key = private_key.get_verifying_key()
    pvtkeystr= private_key.to_string().hex()
    pubkeystr= public_key.to_string().hex()
    return pvtkeystr, pubkeystr

def to_cose_key(pvtkey):
    private_key_bytes = bytes.fromhex(pvtkey)
    private_key = SigningKey.from_string(private_key_bytes, curve=NIST256p)
    public_key = private_key.get_verifying_key()
    pubkeystr= public_key.to_string().hex()
    public_key_bytes=bytes.fromhex(pubkeystr)
    x = public_key_bytes[:32]
    y = public_key_bytes[32:]
    cose_key= {
        1:2,
        3:-7,
        -1:1,
        -2:x,
        -3:y,
    }
    cose_encoded=cbor2.dumps(cose_key)
    return cose_encoded

def get_algo():
    return -7

def sign_challenge(pvtkey, challenge):
    private_key_bytes = bytes.fromhex(pvtkey)
    private_key = SigningKey.from_string(private_key_bytes, curve=NIST256p)
    private_key_bytes=private_key.to_der()    
    private_key = load_der_private_key(private_key_bytes, password=None, backend=default_backend())
    signature = private_key.sign(
        challenge,
        ec.ECDSA(hashes.SHA256())
    )
    return signature 

def gen_certificate(pvtkey):
    private_key_bytes = bytes.fromhex(pvtkey)
    private_key = SigningKey.from_string(private_key_bytes, curve=NIST256p)
    private_key_bytes=private_key.to_der()    
    private_key = load_der_private_key(private_key_bytes, password=None, backend=default_backend())
    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"WB"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Kolkata"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"AdityaMitra"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"example.com"),
    ])
    builder = builder.subject_name(name)
    builder = builder.issuer_name(name)
    builder = builder.public_key(public_key)
    builder = builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(days=1))
    builder = builder.not_valid_after(datetime.datetime.today() + datetime.timedelta(days=365))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )
    certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend())
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    return cert_der

def hash_data(data):
    return sha256(data).digest()

import base64
def auth(rpid, tosign):
    reload_keys()
    if rpid not in current_keys:
        return None, None, None
    
    keys=current_keys[rpid]
    for key in keys:
        keyb64=base64.b64encode(key).decode()
        print(keyb64,' ',keys[key]['userentity']['name'])

    if len(keys)>1:
        keyb64=input('Select key: ')
        key=base64.b64decode(keyb64.encode())
        if key not in keys:
            return None, None, None
    
    credid=keys[key]['publickeyentity']['id']
    userid=keys[key]['userid']
    pvtkey=keys[key]['pvtkey']
    signed=sign_challenge(pvtkey, tosign)

    return signed, userid, credid
    