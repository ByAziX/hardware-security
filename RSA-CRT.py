# Conversion en binaire avec binascii
from binascii import unhexlify, hexlify

# Chargement des fonctions cryptographiques nécessaires de PyCryptodome
# Chargement du RSA :
from Crypto.PublicKey import RSA
# /!\ Ajouter PKCS_v1_5 et SHA256

from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from binascii import unhexlify, hexlify
from gmpy2 import invert, powmod, gcd, gcdext


# output est le résultat de la signature du message "Hello World!" par le protocole PKCS#1v1.5 utilisant la fonction de hachage 
# SHA-256
output = "r4F09799F6A59081B725599753330B7A2440ABC42606601622FE0C582646E32555303E1062A2989D9B4C265431ADB58DD\nz00\nr85BB33C4BB237A311BC40C1279528FD6BB36F94F534A4D8284A18AB8E5670E734C55A6CCAB5FB5EAE02BA37E2D56648D\nz00\nr7A13BBF17A0E07D607C07CBB72C7A7A77076376E8434CE6E136832DC95DB3D80\nz00"
print(output)

# On affiche le résultat en hexadécimal
newout = output.replace("r", "").replace("\nz00","").replace("\n","")
print(newout)

# Conversion de la signature en binaire
signature = unhexlify(newout)
print(signature)

# Clé publique
e = 0x10001
N = 0x9292758453063D803DD603D5E777D7888ED1D5BF35786190FA2F23EBC0848AEADDA92CA6C3D80B32C4D109BE0F36D6AE7130B9CED7ACDF54CFC7555AC14EEBAB93A89813FBF3C4F8066D2D800F7C38A81AE31942917403FF4946B0A83D3D3E05EE57C6F5F5606FB5D4BC6CD34EE0801A5E94BB77B07507233A0BC7BAC8F90F79

# Message
m = b"Hello World!"

# Hashage du message avec SHA-256 et affichage du hashé (nommé "hash_object")
hash_object = SHA256.new(data=m)
print(hash_object.hexdigest())

# Construction de la clé publique RSA, et affichage en format PEM (les formats DER et OpenSSH sont aussi disponibles) 
key = RSA.construct((N, e))
print(key.exportKey("PEM"))

# Vérification de la signature PKCS v1.5 du message
public_key = RSA.import_key(key.exportKey("PEM"))

# On vérifie la signature
verifier = PKCS1_v1_5.new(public_key)
is_verified = verifier.verify(hash_object, signature)

# Afficher "True" si la signature est vérifiée (utiliser assert)
assert is_verified is True, "La signature n'est pas valide !"
print("La signature est vérifiée.")


# Padding du PKCS#1 v1.5
def build_message(m, N):
    sha_id = "3031300d060960864801650304020105000420"
    N_len = (len(bin(N)) - 2 + 7) // 8
    pad_len = (len(hex(N)) - 2) // 2 - 3 - len(m)//2 - len(sha_id)//2
    padded_m = "0001" + "ff" * pad_len + "00" + sha_id + m
    return padded_m

print("Message:       {}".format(m))

# Encode message
hash_object = SHA256.new(data=m)
hashed_m = hexlify(hash_object.digest()).decode()
padded_m = build_message(hashed_m, N)
msg = int.from_bytes(unhexlify(padded_m), byteorder='big') 
print("Padded/hashed: {}".format(padded_m))








# Signature RSA-CRT

# Paramètres RSA
p = 0xc36d0eb7fcd285223cfb5aaba5bda3d82c01cad19ea484a87ea4377637e75500fcb2005c5c7dd6ec4ac023cda285d796c3d9e75e1efc42488bb4f1d13ac30a57
q = 0xc000df51a7c77ae8d7c7370c1ff55b69e211c2b9e5db1ed0bf61d0d9899620f4910e4168387e3c30aa1e00c339a795088452dd96a9a5ea5d9dca68da636032af

#Calcul de phi et de d
phi = (p-1)*(q-1)
d = invert(e, phi)

#Paramètres CRT : calculs de dp, dq, qinv
dp = d % (p-1)
dq = d % (q-1)
qinv = invert(q, p)


#Calculs internes du CRT : sp, sq et la signature finale (notée s_crt)
sp = powmod(msg, dp, p)
sq = powmod(msg, dq, q)
s_crt = (sq - sp) * qinv % p


#Utiliser la signature précédente correcte, et vérifier que les deux signatures RSA-CRT et non-CRT sont égales
s = int.from_bytes(signature, byteorder='big') 
print("Signature:  {}".format(hex(s)))
print("s == s_crt? {}".format(s == s_crt))