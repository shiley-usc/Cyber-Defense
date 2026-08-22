import base64
import secrets

print('APP_SECRET=' + secrets.token_urlsafe(48))
print('EVIDENCE_ENCRYPTION_KEY=' + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())
print('VELOCIRAPTOR_INITIAL_ADMIN_PASSWORD=' + secrets.token_urlsafe(24))
