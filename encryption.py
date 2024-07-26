from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_rsa(data, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(data.encode('utf-8'))
    print("Encrypted data in Rsa",base64.b64encode(ciphertext).decode('utf-8'))

def decrypt_rsa(encrypted_data, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = base64.b64decode(encrypted_data)
    data = cipher.decrypt(ciphertext)
    return data.decode('utf-8')


def encrypt_aes(data):
    data_bytes = data.encode('utf-8')
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data_bytes)
    print("key", base64.b64encode(key).decode('utf-8'))
    print("nonce",base64.b64encode(cipher.nonce).decode('utf-8'))
    print("tag", base64.b64encode(tag).decode('utf-8'))
    print("ciphertext", base64.b64encode(ciphertext).decode('utf-8'))


def decrypt_aes(key,nonce,tag,ciphertext):
    key = base64.b64decode(key)
    nonce = base64.b64decode(nonce)
    tag = base64.b64decode(tag)
    ciphertext = base64.b64decode(ciphertext)
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data_bytes = cipher.decrypt_and_verify(ciphertext, tag)
    return data_bytes.decode('utf-8')

def encrypt_des(data):
    data_bytes = data.encode('utf-8')
    key = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data_bytes)
    print("key", base64.b64encode(key).decode('utf-8'))
    print("nonce",base64.b64encode(cipher.nonce).decode('utf-8'))
    print("tag", base64.b64encode(tag).decode('utf-8'))
    print("ciphertext", base64.b64encode(ciphertext).decode('utf-8'))


def decrypt_des(key,nonce,tag,ciphertext):
    key = base64.b64decode(key)
    nonce = base64.b64decode(nonce)
    tag = base64.b64decode(tag)
    ciphertext = base64.b64decode(ciphertext)
    cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
    data_bytes = cipher.decrypt_and_verify(ciphertext, tag)
    return data_bytes.decode('utf-8')

if __name__ == "__main__":
    print('''Enter Function to Done
            1.AES Encryption
            2.AES Decryption
            3.DES Encryption
            4.DES Decryption
            5.RSA Encryption
            6.RSA Decryption''')
    a=int(input("Enter option please:"))
    if a==1:
        b=input("Enter String to be encoded:")
        c=encrypt_aes(b)
    elif a==2:
        k=input("Enter key:")
        n=input("Enter Nonce value:")
        t=input("Enter Tag value")
        b=input("Enter Ciphertext")
        c=decrypt_aes(k,n,t,b)
        print("Decrypted data  in AES:",c)
    elif a==3:
        b=input("Enter String to be encoded:")
        c=encrypt_des(b)
    elif a==4:
        k=input("Enter key:")
        n=input("Enter Nonce value:")
        t=input("Enter Tag value")
        b=input("Enter Ciphertext")
        c=decrypt_des(k,n,t,b)
        print("Decrypted data  in DES:",c)
    elif a==5:
        b=input("Enter String to be Encoded")
        private_key, public_key = generate_rsa_keys()
        encrypt_rsa(b,public_key)
        with open("privatebackup.pem","wb+") as x:
            x.write(private_key)
            print("private key has been saved locally")
    elif a==6:
        b=input("Enter String to be Decoded")
        with open("privatebackup.pem","rb") as x:
            k=x.read()
            
        c=decrypt_rsa(b,k)
        print("Decrypted Data in RSA:",c)
        
    else:
        print("Invalid option")


