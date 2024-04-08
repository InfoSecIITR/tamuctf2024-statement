from pwn import *

dataset = dict()
flagset = dict()
while True:
    print(len(dataset))
    io = remote("tamuctf.com", 443, ssl=True, sni="emoji-group")
    io.recvline()
    io.sendline(b''.join(i.to_bytes(1,'big') if i!=0x0a else b'' for i in range(0,128)))
    res = io.recvline()[len("Your cipher text is: "):].strip()#.split(b'\xf0\x9f')
    res = res.replace(b'\xf0\x9f',b' ').replace(b'\xe2',b' ')
    res = res.split(b' ')[1:]
    pt = b''.join(i.to_bytes(1,'big') if i!=0x0a else b'' for i in range(0,128))
    dic = dict()
    for i in range(len(pt)):
        dic[res[i+1]]=pt[i]
    dataset[res[0]] = dic
    if res[0] in flagset:
        for i in flagset[res[0]]:
            print(dataset[res[0]][i],end='')
        exit()
    io.recvuntil(b"The flag is: ")
    res = io.recvline().strip()#.split(b'\xf0\x9f')
    res = res.replace(b'\xf0\x9f',b' ').replace(b'\xe2',b' ')
    res = res.split(b' ')[1:]
    if res[0] in dataset:
        for i in res[1:]:
            print(chr(dataset[res[0]][i]),end='')
        exit()
    flagset[res[0]] = res[1:]
    io.close()