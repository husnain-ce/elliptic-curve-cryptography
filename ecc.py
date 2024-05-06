#-----------------------------------------------------------------------IMPORTING REQUIRED LIBRARIES------------------------------------------------------------
from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets, binascii
#---------------------------------------------------------------------------------------------------------------------------------------------------------------
#-----------------------------------------------------------------------SUPPORTING FUNCTIONS------------------------------------------------------------



#-----------------------------------------------------------------------AES Galois Field Encryption----------------------------------------------------
# THE MAIN TASK OF THIS FUNCTION IS TO ENCRYPT THE INPUT MESSAGE USING THE gcm MODE OF AES.


def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)
# THE MAIN TASK OF THIS FUNCTION IS TO DECRYPT THE INPUT MESSAGE USING THE gcm MODE OF AES.


def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext
# THE MAIN TASK OF THIS FUNCTION IS TO CONVERT THE POINT(X,Y) TO A 256-BIT KEY.


def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()
# A RANDOM CURVE IS GENERATED WHICH IS NOT A KOBLITZ CURVE I.E SECP256R1.
curve = registry.get_curve('secp256r1')

# ECC ENCRYPTION METHOD.
def encrypt_ECC(msg, pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)
# ECC DECRYPTION METHOD.

def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext


#-----------------------------------------------------------------------SUPPORTING FUNCTIONS END------------------------------------------------------------

#-----------------------------------------------------------------------MAIN FUNCTION------------------------------------------------------------
print('---------------------------ECC PROTOCOL----------------------------')
print('Step 1: Input Message')
msg = input('Enter the message :')
msg=msg.encode()
print("original msg:", msg.decode())
print('')
print('Step 2: Key Generation')
privKey = secrets.randbelow(curve.field.n)
pubKey = privKey * curve.g
print('Private key :',privKey)
print('Public key :',pubKey)
print('')
print('Step 3: ECC Encryption')
encryptedMsg = encrypt_ECC(msg, pubKey)
encryptedMsgObj = {
    'ciphertext': binascii.hexlify(encryptedMsg[0]),
    'nonce': binascii.hexlify(encryptedMsg[1]),
    'authTag': binascii.hexlify(encryptedMsg[2]),
    'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
}
print("encrypted msg:", encryptedMsgObj)
print('')
print('Step 4: ECC Decryption')
decryptedMsg = decrypt_ECC(encryptedMsg, privKey)
print("decrypted msg:", decryptedMsg.decode())