from Crypto.PublicKey import RSA
from Crypto.Util.number import *
from base64 import b64decode, b64encode

with open('public.pem', 'r') as f:
    pub_key = RSA.importKey(f.read())

with open('flag.txt.enc', 'rb') as f:
    flag_enc = f.read()

with open('private.pem', 'r') as f:
    priv_key = f.read()

partial_priv_key = priv_key.removesuffix("\n-----END PRIVATE KEY-----")
partial_priv_key = b64decode(partial_priv_key)
partial_priv_key = """02818100f45ab61bc6106f792458be4395d3ea267eeb704bac08a0299e0980aae4c6e81dd667f0d0c21f2f98eba6fe1bf18c6497b0a8429048bc077008ca1f1a2e9de157a7a031574ae4056b4e44d9e35dfb61b165ef3a0049cc69bc089412fb156d52961ce25d509d8690a5cd3f4829524cf1bbef91f90e727cb78acaa0d42eafefe9730281803d415340235bac7e1983d7533034fed5d0a6ee576803319229e18a2389593fc0131cc953c26d79050b27710310d1ba69c4aec0c866d1630b850d091ba8087a347238165222a8c44961873e6914d576d40f3d222dbd611d3a8930059829626ce119c96f1e8d189021776362e02c8e1a6ba3629a8d9e9d6a7d936199c8ff54e781028181009803b2d53673d51595320c33b98b1b59158e5ccf06d85ae36928da3df69373a5d453d771d7c254f71a6b4a1c9239d7feb26d0af3fdfbd3d8b3ef22484485fdc16d4bf046311607f508bd369c0744b3330c8a361825d1205a552fe15b08aa793d5ffcc736b6b91755be8946d846160e30efca6d19bac9b1d98b53608d26f0e6d702818067a4fc685e86019d2cf35e197c4732cd91ab65943f309ed6f1919d535ff2fb6d382f37c6b16f9dfac4cf7d03d8867d37fea53748584fd3de6c63310b78e399df221339fb4711d30fdd77df9c0b9d827ded047aedbb412c5452f8e07ec259ee21c77338f4cd257c4443eb494fc141b5f21639a9cb614a4a357f55a44e037b46bb"""

nums = partial_priv_key.split("0281")[1:]
nums = [int(num[2:], 16) for num in nums]
q = nums[0]
n = pub_key.n
p = n // q
assert isPrime(p) and isPrime(q) and n == pub_key.n

phi = (p-1)*(q-1)
d = inverse(pub_key.e, phi)
flag_enc = int.from_bytes(flag_enc, 'big')
flag = pow(flag_enc, d, n)
flag = long_to_bytes(flag)
print(flag)