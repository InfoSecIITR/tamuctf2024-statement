from Crypto.Util.strxor import strxor
from requests import Session
from base64 import b64decode, b64encode

s = Session()
base_url = "https://flipped.tamuctf.com/"

r = s.get(base_url)
enc = r.cookies.get("session")
enc = b64decode(enc)
iv = enc[:16]
ct = enc[16:]
default_cookie = b'{"admin": 0, "username": "guest"}'
target_cookie = b'{"admin": 1, "username": "guest"}'

new_iv = strxor(iv, strxor(default_cookie[:16], target_cookie[:16]))
s.cookies.set("session", b64encode(new_iv + ct).decode())
r = s.get(base_url)
print(r.text)