from Crypto.PublicKey import RSA
from Crypto.Cipher import  PKCS1_OAEP
from Crypto.Random import get_random_bytes
from PIL import Image
import io
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_rsa(image_path, public_key):
    with Image.open(image_path) as img:
        byte_arr = io.BytesIO()
        img.save(byte_arr, format=img.format)
        img_bytes = byte_arr.getvalue()

    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)

    encrypted_data = b''
    chunk_size = rsa_key.size_in_bytes() - 42  
    for i in range(0, len(img_bytes), chunk_size):
        chunk = img_bytes[i:i+chunk_size]
        encrypted_data += cipher.encrypt(chunk)
    
    with open(image_path,"wb") as x:
        x.write(encrypted_data)
        x.close()
def decrypt_rsa(encrypted_data, private_key,image_path):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)

    decrypted_data = b''
    chunk_size = rsa_key.size_in_bytes()
    for i in range(0, len(encrypted_data), chunk_size):
        chunk = encrypted_data[i:i+chunk_size]
        decrypted_data += cipher.decrypt(chunk)

    with open(image_path,"wb") as x:
        x.write(decrypted_data)
        x.close()

def xorencryption(d,k):
    e=bytearray(d)
    for i,j in enumerate(e):
        e[i]=j^k
    with open(b,"wb") as x:
        x.write(e)
        x.close()

if __name__=='__main__':
    a=int(input('''Enter option
            1.XOR IMG Encryption
            2.XOR IMG Decryption
            3.RSA IMG Encryption
            4.RSA IMG Decryption
            '''))
    if a==1:
        b=input("IMG name")
        k=int(input("Enter key for encryption"))
        c=open(b,"rb")
        xorencryption(c.read(),k)
        print("encryption Completed")
    elif a==2:
        b=input("IMG name")
        k=int(input("Enter key for decryption"))
        c=open(b,"rb")
        xorencryption(c.read(),k)
        print("decryption Completed")
    elif a==3:
        b=input("Enter IMG to be Encoded")
        private_key, public_key = generate_rsa_keys()
        encrypt_rsa(b,public_key)
        with open("privatebackup.pem","wb+") as x:
            x.write(private_key)
            print("private key has been saved locally")
    elif a==4:
        b=input("Enter IMG to be Decoded")
        with open("privatebackup.pem","rb") as x:
            k=x.read()
        c=open(b,"rb")   
        c=decrypt_rsa(c.read(),k,b)
        print("Decrypted Data in RSA")
        
    else:
        print("Invalid option")