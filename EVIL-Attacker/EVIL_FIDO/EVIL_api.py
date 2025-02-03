import hashlib
from EVIL_FIDO.EVIL_core import *
import uuid
import base64
import cbor2

class EvilAPI:
	version='1.0'
	
	def __init__(self, handle=None):
		self.handle=handle
		
	def skip_rp_verify():
		return True	
	
	
	def get_assertion(
		self,
		rp_id,
		client_data,
		timeout=0,
		platform_attachment=0,
		user_verification=0,
		allow_credentials=None,
		extensions=None,
		key_id=None,
		event=None,
	):
		rpidhash=hashlib.sha256(rp_id.encode()).digest()
		flag=b'\x05'
		signcount=bytes(4)
		authdata=rpidhash+flag+signcount
		tosign=authdata+client_data.hash


		signature, user_id, credid=auth(rp_id, tosign)

		credential_descriptor={"type": "webauthn.get", "id":credid}
		return credential_descriptor, authdata, signature, user_id