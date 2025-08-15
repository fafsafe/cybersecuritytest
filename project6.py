import hashlib
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

def hash_function(identifier):
    return int(hashlib.sha256(identifier.encode()).hexdigest(), 16)

def generate_private_exponent():
    return random.randint(1, 100) 

def generate_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
def encrypt(public_key, plaintext):
    cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def decrypt(private_key, ciphertext):
    cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

class AdditiveHomomorphicEncryption:
    def __init__(self, public_key):
        self.public_key = public_key

    def encrypt(self, value):
        return encrypt(self.public_key, str(value).encode())

    def decrypt(self, ciphertext, private_key):
        return decrypt(private_key, ciphertext)

class Party1:
    def __init__(self):
        self.k1 = generate_private_exponent()
        self.set_U = ["item1", "item2", "item3"] 

    def round1(self):
        hashed_values = [hash_function(v) * self.k1 for v in self.set_U]
        return shuffled(hashed_values)

class Party2:
    def __init__(self):
        self.k2 = generate_private_exponent()
        self.set_P2 = [("itemA", 10), ("itemB", 20)]
        self.pk, self.sk = generate_keypair()
        self.encryption_scheme = AdditiveHomomorphicEncryption(self.pk)

    def round2(self, hashed_values):
        processed_hashes = [h * self.k2 for h in hashed_values]
        encrypted_pairs = [(h, self.encryption_scheme.encrypt(str(t).encode())) for w, t in self.set_P2]
        return shuffled(list(zip(processed_hashes, encrypted_pairs)))

def execute_protocol():
    P1 = Party1()
    P2 = Party2()

    hashed_values = P1.round1()
    
    P2_data = P2.round2(hashed_values)
    
    intersection_set = set() 
    for (hashed_w, enc_t) in P2_data:
        final_hash = hashed_w * P1.k1 * P2.k2
        if final_hash in hashed_values: 
            intersection_set.add(final_hash)
    
    total_sum = sum(int(decrypt(P2.sk, enc_t)) for (_, enc_t) in P2_data if _ in intersection_set)

    print("交集和:", total_sum)

def shuffled(data):
    random.shuffle(data)
    return data

if __name__ == "__main__":
    execute_protocol()
