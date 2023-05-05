from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii
# pseudo code for a transmission session
# SENDER MODULE
# ABOUT SENDING KEY FILE FROM SENDER
		# Store the hash as a file 
            #sha_hash = get_sha256_hash(hash)

        # Encrypt the hash with senders private key, call it the digital signature
		# Write the digital signature into to the message file. 
        # Store the digital signature as a file 

            #digital_sig = get_rsa_signature(hash, key_pair)
            #Sender.write_text_file(filename, digital_sig)

        # Transmit publicKey
            #send_file(pub_file)

        # Wait for confirmation that key received
             #receive_message()


# RECEIVER MODULE
# ABOUT RECEIVING KEY AND CHECKING VALIDATION

        # Wait for sender to msg that public key is ready to be sent, and then acknowledge
            #print("Waiting for sender to get public key ready...")
            #receive_message()
            #send_message("ack")

        # receive the public key and send acknowledgement
            #receive_file()
            #send_message("ack")

        # Verify that calculated hash matches the digital signature that was sent
            #self.receive_message()
            #log.info("Verifying that signature matches calculated hash...")
            #cipher = PKCS1_v1_5.new(pub_key)
            #is_match = cipher.verify(sha_hash, dig_sig_as_bin_str)
            #if is_match:
                #self.send_message("valid")
            #else:
                #self.send_message('invalid')
       
#KEYRELATED MODULE
        # generate RSA key (contains both public and private data)
             #rsa_key = kg.generate_rsa_key_pair()

        # write key to file (PEM_FILE)
            # write_rsa_keys_to_file(cool_file.pem)

        #read key from file (PEM_FILE)
            # import_rsa_key_from_file(cool_file.pem)

#PEM_FILE: a container format that may just include the public certificate or the entire certificate chain 
#(private key, public key, root certificates): Private Key. Server Certificate (crt, puplic key) 
#(optional) Intermediate CA and/or bundles if signed by a 3rd party.

# Generate 2048-bit RSA key pair (private + public key)
key = RSA.generate(2048)
f = open('mykey.pem','wb')
f.write(key.export_key('PEM'))
f.close()

f = open('mykey.pem','r')
keyPair = RSA.import_key(f.read())
pubKey = keyPair.public_key()

# Sign the message using the PKCS#1 v1.5 signature scheme (RSASP1)
msg = b'23/04/2023 is sunday, not monday'
hash = SHA256.new(msg)
signer = PKCS115_SigScheme(keyPair)
signature = signer.sign(hash)
print("Signature:", binascii.hexlify(signature))


# Verify valid PKCS#1 v1.5 signature (RSAVP1)
msg = b'23/04/2023 is sunday, not monday'
hash = SHA256.new(msg)
verifier = PKCS115_SigScheme(pubKey)
try:
    verifier.verify(hash, signature)
    print("Signature is valid.")
except:
    print("Signature is invalid.")

# Verify invalid PKCS#1 v1.5 signature (RSAVP1)
msg = b'23/04/2023 is monday, not sunday'
hash = SHA256.new(msg)
verifier = PKCS115_SigScheme(pubKey)
try:
    verifier.verify(hash, signature)
    print("Signature is valid.")
except:
    print("Signature is invalid.")

