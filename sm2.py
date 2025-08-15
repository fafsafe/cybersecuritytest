import os
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from hashlib import sha256
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import binascii

class SM2:
    def __init__(self):
        self.curve = SECP256k1

    def generate_keypair(self):
        private_key = SigningKey.generate(curve=self.curve)
        public_key = private_key.get_verifying_key()
        return private_key, public_key

    def encrypt(self, public_key, plaintext):
        k = os.urandom(32) 
        k_int = int.from_bytes(k, byteorder='big') % self.curve.order
        P = k_int * self.curve.generator 
        x1, y1 = P.x(), P.y()

        Z = sha256((public_key.to_string() + P.to_bytes()).encode()).digest()
        cipher = AES.new(Z[:16], AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        return (x1, y1, ciphertext, cipher.iv)

    def decrypt(self, private_key, encrypted_data):
        x1, y1, ciphertext, iv = encrypted_data
        P = private_key.get_verifying_key() * (int.from_bytes(os.urandom(32), byteorder='big') % self.curve.order)  # 计算 P
        Z = sha256((private_key.to_string() + P.to_bytes()).encode()).digest()

        cipher = AES.new(Z[:16], AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        return plaintext

    def sign(self, private_key, message):
        return private_key.sign(message)

    def verify(self, public_key, message, signature):
        return public_key.verify(signature, message)

if __name__ == "__main__":
    sm2 = SM2()

    private_key, public_key = sm2.generate_keypair()

    message = b"Hello, SM2!"

    signature = sm2.sign(private_key, message)
    print("Signature:", binascii.hexlify(signature))

    is_valid = sm2.verify(public_key, message, signature)
    print("Signature valid:", is_valid)
    
    encrypted_data = sm2.encrypt(public_key, message)
    print("Encrypted data:", encrypted_data)

    decrypted_message = sm2.decrypt(private_key, encrypted_data)
    print("Decrypted message:", decrypted_message.decode())
