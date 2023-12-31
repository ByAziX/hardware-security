from binascii import unhexlify, hexlify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from gmpy2 import invert, powmod, gcd, gcdext
from random import randint, sample
import os




# output est le résultat de la signature du message "Hello World!" par le protocole PKCS#1v1.5 utilisant la fonction de hachage 
# SHA-256
print('\n---------------------Signature-----------------')
output = "r4F09799F6A59081B725599753330B7A2440ABC42606601622FE0C582646E32555303E1062A2989D9B4C265431ADB58DD\nz00\nr85BB33C4BB237A311BC40C1279528FD6BB36F94F534A4D8284A18AB8E5670E734C55A6CCAB5FB5EAE02BA37E2D56648D\nz00\nr7A13BBF17A0E07D607C07CBB72C7A7A77076376E8434CE6E136832DC95DB3D80\nz00"
print(output)

# On affiche le résultat en hexadécimal
newout = output.replace("r", "").replace("\nz00","").replace("\n","")
print(newout)

# Conversion de la signature en binaire
signature = unhexlify(newout)
print(signature)

#Clé publique 
e = 0x10001
N = 0x9292758453063D803DD603D5E777D7888ED1D5BF35786190FA2F23EBC0848AEADDA92CA6C3D80B32C4D109BE0F36D6AE7130B9CED7ACDF54CFC7555AC14EEBAB93A89813FBF3C4F8066D2D800F7C38A81AE31942917403FF4946B0A83D3D3E05EE57C6F5F5606FB5D4BC6CD34EE0801A5E94BB77B07507233A0BC7BAC8F90F79

#Message
m = b"Hello World!"

#Hashage du message avec SHA-256 et affichage du hashé (nommé "hash_object")
hash_object = SHA256.new(data=m)
print(hash_object.hexdigest())
#Construction de la clé publique RSA, et affichage en format PEM (les formats DER et OpenSSH sont aussi disponibles) 
public_key = RSA.construct((N, e))
print(public_key.exportKey('PEM'))

#Vérification de la signature PKCS v1.5 du message
verifier = PKCS1_v1_5.new(public_key)
is_verified = verifier.verify(hash_object, signature)

#Afficher "True" si la signature est vérifiée (utiliser assert)
assert is_verified is True, "La signature n'est pas valide !"
print(is_verified)




# Padding du PKCS#1 v1.5
def build_message(m, N):
    sha_id = "3031300d060960864801650304020105000420"
    N_len = (len(bin(N)) - 2 + 7) // 8
    pad_len = (len(hex(N)) - 2) // 2 - 3 - len(m)//2 - len(sha_id)//2
    padded_m = "0001" + "ff" * pad_len + "00" + sha_id + m
    return padded_m


# Encode message
print('\n---------------------Encode message-----------------')
hashed_m = hexlify(hash_object.digest()).decode()
padded_m = build_message(hashed_m, N)
msg = int.from_bytes(unhexlify(padded_m), byteorder='big') 
print("Hashed:        {}".format(hashed_m))
print("Padded/hashed: {}".format(padded_m))
print("Message:       {}".format(hex(msg)))







# Signature RSA-CRT
print('\n---------------------Signature RSA-CRT-----------------')
# Paramètres RSA
p = 0xc36d0eb7fcd285223cfb5aaba5bda3d82c01cad19ea484a87ea4377637e75500fcb2005c5c7dd6ec4ac023cda285d796c3d9e75e1efc42488bb4f1d13ac30a57
q = 0xc000df51a7c77ae8d7c7370c1ff55b69e211c2b9e5db1ed0bf61d0d9899620f4910e4168387e3c30aa1e00c339a795088452dd96a9a5ea5d9dca68da636032af

# Calcul de phi et de d
phi = (p - 1) * (q - 1)
d = invert(e, phi)

# Paramètres CRT : calculs de dp, dq, qinv
dp = d % (p - 1)
dq = d % (q - 1)
qinv = invert(q, p)

# Calculs internes du CRT : sp, sq et la signature finale (notée s_crt)
sp = powmod(msg, dp, p)
sq = powmod(msg, dq, q)
h = (qinv * (sp - sq)) % p
s_crt = sq + h * q

# Utiliser la signature précédente correcte, et vérifier que les deux signatures RSA-CRT et non-CRT sont égales
s = int.from_bytes(signature, byteorder='big') 
print("Signature:  {}".format(hex(s)))
print("s == s_crt? {}".format(s == s_crt))







# Injection de fautes (bit flip) aléatoires dans sp
print('\n---------------------Attacking with bit flip-----------------')
from random import randint, sample

# Inversion arbitraire de bits dans sp, et calcul de la signature corrompue
num_bits_to_flip = randint(1, 1024)  # Choisir un nombre aléatoire entre 1 et 1024

# Indices aléatoires des bits à inverser
indices_to_flip = sample(range(1024), num_bits_to_flip)

# Inversion des bits aux indices sélectionnés
sp_corrupted = sp
for index in indices_to_flip:
    sp_corrupted ^= (1 << index)

# Calcul de la signature corrompue
h = (qinv * (sp_corrupted - sq)) % p
s_corrupted = sq + h * q

# Vérification de la signature corrompue
is_verified = verifier.verify(hash_object, s_corrupted)
if is_verified:
    print("La signature corrompue est vérifiée.")
else:
    print("La signature corrompue n'est pas vérifiée. Procéder à l'attaque !")




# Variante de l'attaque de Bellcore n°1 : retrouver p et q à partir de la signature correcte et fautée (DFA)
print("\n---------------------Attacking with DFA-----------------")
from math import gcd 
print("\nSignature corrompu :", hex(s_corrupted))
print("\nSignature non corrompu :", hex(s_crt))
print("\nN :", hex(N))

diff = abs(s_corrupted - s_crt)
print("\ndiff :", hex(diff))

q_dfa = gcd(diff, N)

if q_dfa == 1:
    print("q n'a pas été trouvé !")
    exit()

p_dfa = N // q_dfa

print("\np_found =" ,hex(p_dfa))
print("\nq_found =" ,hex(q_dfa))

# Vérifier que p et q sont corrects
assert p_dfa * q_dfa == N, "p et q ne sont pas corrects !"
print("p et q sont corrects !")





# Variante de l'attaque de Bellcore n°2 : retrouver p et q à partir de seulement une signature fautée (SFA)

print("\n---------------------Attacking with SFA-----------------")

delta = (powmod(s_corrupted, e, N) - msg) % N
p_sfa = gcd(delta, N)
q_sfa = N // p_sfa

print("\np_sfa =" ,hex(p_sfa))
print("\nq_sfa =" ,hex(q_sfa))
assert p_sfa * q_sfa == N, "p et q ne sont pas corrects !"
print("p et q sont corrects !")

# Calcul de d

phi_dfa = (p_dfa - 1) * (q_dfa - 1)
d_dfa = invert(e, phi_dfa)
phi_sfa = (p_sfa - 1) * (q_sfa - 1)
d_sfa = invert(e, phi_sfa)

print("\nd_dfa =" ,hex(d_dfa))
print("\nd_sfa =" ,hex(d_sfa))

# Vérifier que d est correct
assert d_dfa == d, "d n'est pas correct !"
assert d_sfa == d, "d n'est pas correct !"
print("d est correct !")


# Maintenant que l'on a retrouvé tous les paramètres, on peut déchiffrer le message

print("\n---------------------Déchiffrement-----------------")
from Crypto.Util.number import inverse




# Calcul de d

phi_dfa = (p_dfa - 1) * (q_dfa - 1)
d_dfa = invert(e, phi_dfa)
phi_sfa = (p_sfa - 1) * (q_sfa - 1)
d_sfa = invert(e, phi_sfa)

print("\nd_dfa =" ,hex(d_dfa))
print("\nd_sfa =" ,hex(d_sfa))

# Paramètres CRT : calculs de dp, dq, qinv
dp_dfa = d_dfa % (p_dfa - 1)
dq_dfa = d_dfa % (q_dfa - 1)
qinv = invert(q_dfa, p_dfa)


def pad_for_encryption(message, modulus_length):
    ''' 
    Pad the given message using PKCS#1 v1.5 padding scheme for encryption.
    
    modulus_length: Length of the RSA modulus in bytes.
    message: Message to be padded as bytes.
    '''
    
    # Maximum message length: modulus length - 3 (for 00, 02, and 00 bytes) - 8 (minimum PS length)
    max_msg_length = modulus_length - 11
    
    if len(message) > max_msg_length:
        raise ValueError(f"Message is too long. Maximum length for given modulus is {max_msg_length} bytes.")
    
    # Generate PS sequence
    ps_length = modulus_length - len(message) - 3
    ps = os.urandom(ps_length).replace(b'\x00', b'\x01')  # Ensure there are no zero bytes in PS
    
    return b'\x00\x02' + ps + b'\x00' + message

modulus_length = (N.bit_length() + 7) // 8
padded_message = pad_for_encryption(m, modulus_length)
print("Padded message:", padded_message)


def remove_padding(padded_message):
    # Locate the second 0x00 byte in the padded message (the one that separates PS from the actual message)
    index = padded_message.find(b'\x00', 2)
    
    if index == -1:
        raise ValueError("Invalid padding structure. 0x00 byte separator not found.")
    
    return padded_message[index+1:]

# Convert padded message from bytes to integer
padded_message_int = int.from_bytes(padded_message, byteorder='big')

# Encrypt using RSA
ciphertext_int = pow(padded_message_int, e, N)

# Decrypt using CRT
m1 = pow(ciphertext_int, dp_dfa, p_dfa)
m2 = pow(ciphertext_int, dq_dfa, q_dfa)
h = (qinv * (m1 - m2)) % p_dfa
decrypted_message_int = m2 + h * q_dfa

# Convert decrypted integer back to bytes
decrypted_message = int(decrypted_message_int).to_bytes((decrypted_message_int.bit_length() + 7) // 8, byteorder='big')

# Remove padding
depadded_message = remove_padding(decrypted_message)

print("Message original:", m)
print("Message chiffré:", ciphertext_int)
print("Message déchiffré (sans padding):", depadded_message.decode("UTF-8"))



print('\n---------------------Vérification signature RSA-CRT-----------------')
depadded_message_hash = SHA256.new(data=depadded_message)
# Vérifiez la signature s_crt avec la clé publique
clef_publique_int = powmod(s_crt, e, N)

# Convertir mpz en int standard, puis en bytes
clef_publique_bytes = int(clef_publique_int).to_bytes((clef_publique_int.bit_length() + 7) // 8, byteorder='big')

def remove_padding_by_sha_id(padded_message_bytes, sha_id):
    sha_id_index = padded_message_bytes.find(sha_id)
    
    if sha_id_index == -1:
        raise ValueError("Invalid padding structure. SHA ID not found.")
    
    return padded_message_bytes[sha_id_index + len(sha_id):]

# Retirer le padding en utilisant la méthode basée sur sha_id
depadded_message_sha_id_method = remove_padding_by_sha_id(clef_publique_bytes, bytes.fromhex("3031300d060960864801650304020105000420"))

# Comparez le hash obtenu à votre hash original
print("Hash original:", hexlify(depadded_message_hash.digest()))
print("Hash obtenu:", hexlify(depadded_message_sha_id_method))
if hexlify(depadded_message_hash.digest()) == hexlify(depadded_message_sha_id_method):
    print("La signature est valide!")
else:
    print("La signature n'est pas valide!")






# Ecrire le schéma de protection "BOS Algorithm", et tenter de reproduire les fautes qui contournent cette protection. Idem pour la variante "BOS+".

# Implementing BOS Algorithm for protection
print("\n---------------------BOS Algorithm-----------------")



def BOS_protection(m, d, N, p, q):
    # BOS Algorithm for protection
    
    # Generate two 80-bit primes
    t1 = randint(2**79, 2**80)
    t2 = randint(2**79, 2**80)
    
    # Compute derived values
    dp = d % ((p-1) * t1)
    dq = d % ((q-1) * t2)
    et1 = invert(d, t1)
    et2 = invert(d, t2)
    
    # BOS algorithm steps for protection
    Sp = powmod(m, dp, p * t1)
    Sq = powmod(m, dq, q * t2)
    
    # Chinese Remainder Theorem (CRT) to compute S
    M1, M2 = q * t2, p * t1
    M = M1 * M2
    inv_M1 = invert(M1, p * t1)
    inv_M2 = invert(M2, q * t2)
    S = (Sq * M1 * inv_M1 + Sp * M2 * inv_M2) % (N * t1 * t2)
    
    c1 = (m - powmod(S, et1, t1) + 1) % t1
    c2 = (m - powmod(S, et2, t2) + 1) % t2
    
    Sig = powmod(S, c1 * c2, N)
    
    return Sig


# Implementing Vigilant Scheme for RSA-CRT protection
print("\n---------------------Vigilant Scheme-----------------")
