from pwn import *
from base64 import b64decode

context.log_level = "debug"
io = remote("tamuctf.com", 443, ssl=True, sni="criminal")


def get_enc_flag(payload):
    io.sendlineafter(b"Append whatever you want to the flag: ", payload)
    cipher = io.recvline().strip()
    cipher = b64decode(cipher)
    return cipher


flag_pos = b"gigem{"
while True:
    len_map = {}
    payloads = []
    ciphers = []
    for i in range(33, 128):
        payload = (flag_pos+bytes([i]))*10
        payloads.append(payload)
        ciphers.append(get_enc_flag(payload))

    min_len = min([len(c) for c in ciphers])
    for i in range(len(ciphers)):
        if len(ciphers[i]) == min_len:
            flag_pos = payloads[i][:len(payloads[i])//10]
            break

    print(flag_pos)