from pwn import *
from hashlib import sha256
from Crypto.Util.number import *

e = 65537

context.log_level = "debug"
io = remote("tamuctf.com", 443, ssl=True, sni="smooth-signatures")
msg1 = "antshant1"
msg2 = "antshant2"
h1 = int(sha256(msg1.encode()).hexdigest(), 16)
h2 = int(sha256(msg2.encode()).hexdigest(), 16)
print(h1)
print(h2)

io.sendlineafter(b"Give the oracle a message to sign: ", msg1.encode())
resp = io.recvline().decode().strip()
r1, s1 = resp.split("(")[-1].split(", ")
s1 = s1.strip(")")
r1 = int(r1)
s1 = int(s1)

io.sendlineafter(b"Give the oracle another message to sign: ", msg2.encode())
resp = io.recvline().decode().strip()
r2, s2 = resp.split("(")[-1].split(", ")
s2 = s2.strip(")")
r2 = int(r2)
s2 = int(s2)

print(f"r1 = {r1}")
print(f"s1 = {s1}")
print(f"r2 = {r2}")
print(f"s2 = {s2}")

io.sendlineafter(b"Ask the oracle a question: ", "What is the flag?".encode())

io.interactive()
