from pwn import *
import math
# from sage.all import *

# context.log_level = "debug"
io = remote("tamuctf.com", 443, ssl=True, sni="qcg")
# io.recvall()
x = [int(io.recvline().strip().decode()) for i in range(10)]
p,q,r,s,t,u = map(int,x[:6])

# q = ap2+bp+c
# r = aq2+bq+c
# s = ar2+br+c
# t = as2+bs+c
# u = a12+bt+c

pp,qq,rr,ss = (r-q),(s-r),(t-s),(u-t)

# pp = a(q+p)(q-p) + b(q-p)
# qq = a(r+q)(r-q) + b(r-q)
# rr = a(s+r)(s-r) + b(s-r)
# ss = a(t+s)(t-s) + b(t-s)

ppp,qqq,rrr = qq*(q-p)-pp*(r-q),rr*(r-q)-qq*(s-r),ss*(s-r)-rr*(t-s)

# ppp = a(r-p)(r-q)(q-p)
# qqq = a(s-q)(s-r)(r-q)
# rrr = a(t-r)(t-s)(s-r)

pppp = qqq*(r-p)*(r-q)*(q-p)-ppp*(s-q)*(s-r)*(r-q)
qqqq = rrr*(s-q)*(s-r)*(r-q)-qqq*(t-r)*(t-s)*(s-r)

m = math.gcd(pppp,qqqq)
# xx = list(factor(m))
# for i in xx:
#     if math.gcd(i[0]-1,(r-p)*(r-q)*(q-p))!=1 or math.gcd(i[0]-1,(q-p))!=1:
#         m//=i[0]
while math.gcd(m,(r-p)*(r-q)*(q-p))>1:
    m//=math.gcd(m,(r-p)*(r-q)*(q-p))

a = (ppp*pow((r-p)*(r-q)*(q-p),-1,m))%m
b = ((pp - a*(q+p)*(q-p)) * pow(q-p,-1,m))%m
c = (q-a*p*p-b*p)%m

print(m,a,b,c)
for i in range(9):
    m = math.gcd(m,(a*x[i]**2+b*x[i]+c)%m-x[i+1])



curr = x[9]
for i in range(5):
    curr = (a*curr**2+b*curr+c)%m
    io.sendline(str(curr).encode())
print(io.recvline())