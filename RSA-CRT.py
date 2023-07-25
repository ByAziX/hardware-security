#Conversion en binaire avec binascii
from binascii import unhexlify, hexlify

#Chargement des fonctions cryptographiques nécessaires de PyCryptodome
#Chargement du RSA :
from Crypto.PublicKey import RSA
#/!\Ajouter PKCS_v1_5 et SHA256

#output est le résultat de la signature du message "Hello World!" par le protocole PKCS#1v1.5 utilisant la fonction de hachage 
#SHA-256
output = "r4F09799F6A59081B725599753330B7A2440ABC42606601622FE0C582646E32555303E1062A2989D9B4C265431ADB58DD\nz00\nr85BB33C4BB237A311BC40C1279528FD6BB36F94F534A4D8284A18AB8E5670E734C55A6CCAB5FB5EAE02BA37E2D56648D\nz00\nr7A13BBF17A0E07D607C07CBB72C7A7A77076376E8434CE6E136832DC95DB3D80\nz00"
print(output)

#On affiche le résultat en hexadécimal
newout = output.replace("r", "").replace("\nz00","").replace("\n","")
print(newout)


sig = unhexlify(newout)
print(sig)




#Clé publique 
e = 0x10001
N = 0x9292758453063D803DD603D5E777D7888ED1D5BF35786190FA2F23EBC0848AEADDA92CA6C3D80B32C4D109BE0F36D6AE7130B9CED7ACDF54CFC7555AC14EEBAB93A89813FBF3C4F8066D2D800F7C38A81AE31942917403FF4946B0A83D3D3E05EE57C6F5F5606FB5D4BC6CD34EE0801A5E94BB77B07507233A0BC7BAC8F90F79

#Message
m = b"Hello World!"

#Hashage du message avec SHA-256 et affichage du hashé (nommé "hash_object")
from Crypto.Hash import SHA256
hash_object = SHA256.new(data=m)
print(hash_object.hexdigest())


#Construction de la clé publique RSA, et affichage en format PEM (les formats DER et OpenSSH sont aussi disponibles) 
key = RSA.construct((N, e))
print(key.exportKey("PEM"))

#Vérification de la signature PKCS v1.5 du message
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from binascii import unhexlify, hexlify

#On charge la clé publique
key = RSA.importKey(open("public.pem").read())

#On charge le message
m = b"Hello World!"

#On charge la signature

#On vérifie la signature
verifier = PKCS1_v1_5.new(key)

#Afficher "True" si la signature est vérifiée (utiliser assert)
assert verifier.verify(SHA256.new(m), sig)
