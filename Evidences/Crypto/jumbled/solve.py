import Crypto.PublicKey.RSA as RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long

with open("public", "r") as f:
    public = f.read().strip().split(" ")
    
with open('private', 'r') as f:
    private = f.read().strip().split(" ")

with open("flag.txt.enc", "rb") as f:
    flag = f.read()

private = [bytes.fromhex(x) for x in private]

for i in range(0, len(private), 10):
    private[i], private[i+8] = private[i+8], private[i]
    private[i+1], private[i+6] = private[i+6], private[i+1]
    private[i+2], private[i+9] = private[i+9], private[i+2]
    private[i+3], private[i+5] = private[i+5], private[i+3]
    private[i+4], private[i+7] = private[i+7], private[i+4]

private = b"".join(private).decode()
print(private)
priv_key = RSA.importKey(private)
public = b"".join([bytes.fromhex(x) for x in public]).decode()
pub_key = RSA.importKey(public)

flag = bytes_to_long(flag)
flag = pow(flag, priv_key.d, priv_key.n)
flag = long_to_bytes(flag)
print(flag)