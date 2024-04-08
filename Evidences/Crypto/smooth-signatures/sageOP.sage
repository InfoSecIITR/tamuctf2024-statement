from Crypto.Util.number import getPrime, long_to_bytes, bytes_to_long
from hashlib import sha256

r1 = 7661708545078818665766604377191052211683754615921420791864403049044142804320121112368217439431653135310192026417321743520601066864420865191046240379894784449137267780575317870283396730578920565066433819433258701471886321438525683441716291668124284433416379015574286403003780947464502424951439558352307245516693574059163055835824614743117228768073846518386795192553045612728984541489181375123347028667316073510386135443114760737178103900060481587249926952313509788159921574624145023358268746901959306145113143294805288072580034256851191556551723876413195011724379030091609107957191909080627334688432238676794293939803
s1 = 17604808791759954751931919980669106796764587468346303552778173463234075189734914000931474470568576571878144635296716614418776952105885273881729187955374044017837658348575190352607905079993835828945219900898009664228980860467864547200888692540070190224950519460746501066148774714375607529686909353660969064557263268778105777646244553011087943116245498943008683478795625347683635568487510476964499192357735969594973256293361246399823835516929194392113930915040953597788403583711278919253730279552566303219175915780577336697530156898646641275780455891123443233280721931167892600531870782634547774188745023917354251442040
r2 = 32677398139810730627816888565819911064663715296057489199800681433931094730195457143748378073157165665588634499937269106426172653401119843362598645416952530111393154712332168823909172602233700982237681135040609203247176205390442967889962560599374013898114405514686070266801921746406312629748878733471576983015133782930858526611910534757538750763072521696992074270423878431075007528926383300276858270203870969125800777445949482954408245035065297789092992133229227346157239912238699662391815688905868587479424814359361521772756609811901800824474128832275704415295464452795155065569728167233080394579999030131669496652981
s2 = 44987805094589309436097796194388342463420325851382378712966408173614890118563931140449028208619263909095221256499742330723991294431224949560770338192698460340821990965422967045934591981912775648779731767686112472777907471561653250768213688197487525002787238219220529965941792469373810116090692894688499359809736441493494678534615306153899301150573051551591581781087031756454898826871815184413107425484778612855225800216439442795112734734938658708526980940318777007340913954184773096732418102023978119696826745663643330974894107798247690839138333376109195578425238387263260434649031625401292746503841550662804025745991

e = 65537

h1 = 67239699911252374140513715243419153382903720299856777543691721453138811744192
h2 = 9338839540825246775525391329497881985278238525229932008378578333251268395800

n1 = abs(r1**e + h1 - s1**e)
n2 = abs(r2**e + h2 - s2**e)
n = gcd(n1, n2)

facs = ECM().factor(n)
print(n,facs)
q = 1

for prime in facs:
    q = lcm(q, prime-1)

d = pow(e, -1, q)
msg = 29743311641806005780189351353178497574719


def sign(n, msg, d):
    h = bytes_to_long(sha256(msg).digest())
    k = 69
    x = pow(h, k, n)
    r = pow(x, d, n)
    s = pow(h+x, d, n)
    return r, s


msg = b"What is the flag?"
print(sign(n, msg, d))
