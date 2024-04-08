from pwn import *

# context.log_level = "debug"
r = remote("tamuctf.com", 443, ssl=True, sni="pcg")
# io.interactive(prompt="")

m = int(r.recvline().decode().strip())

x = [int(r.recvline().decode().strip()) for _ in range(256*3)]

matrix = [[pow(x[i],j,m) for j in range(256)] for i in range(256)]
res = [x[i+1] for i in range(256)]

for i in range(256):
    mult = pow(matrix[i][i],-1,m)
    for j in range(256):
        matrix[i][j] = (matrix[i][j]*mult)%m
    res[i] = (res[i]*mult)%m
    for j in range(256):
        if i==j:
            continue
        mult = matrix[j][i]
        for k in range(256):
            matrix[j][k] = (matrix[j][k]-mult*matrix[i][k])%m
        res[j] = (res[j]-mult*res[i])%m

curr = x[-1]
for i in range(128):
    neww = 0
    for i in range(256):
        neww*=curr
        neww+=res[255-i]
        neww%=m
    curr = neww
    r.sendline(str(curr).encode())

print(r.recvline())