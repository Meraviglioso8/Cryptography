from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii
# pseudo code for a transmission session
# DEMO SENDER MODULE
# ABOUT SENDING KEY FILE FROM SENDER
		# Store the hash as a file named "message.dd" (configured in sender settings)

            #sha_hash = self.get_sha256_hash(hash)
            #filename = self.settings["hashFile"]
            #Sender.make_directory(filename)
            #Sender.write_text_file(filename, sha_hash.hexdigest().upper())

        # Encrypt the hash with senders private key, call it the digital signature
		# Write the digital signature (in base-16) to the log file. (used base-64)
        # Store the digital signature as a file named "message.ds-msg"

            #digital_sig = self.get_rsa_signature(hash, key_pair)
            #filename = self.settings["signatureFile"]
            #Sender.make_directory(filename)
            #log.info("Writing digital signature to file {}".format(filename))
            #Sender.write_text_file(filename, digital_sig)

        # Tell receiver ready to transmit and wait for an 'ack'
            #self.send_message("Ready to send public key")
            #response = self.receive_message()

        # Transmit publicKey
            #pub_file = self.settings["pubKey"]
            #self.send_file(pub_file)

        # Wait for confirmation that key received
             #self.receive_message()

# DEMO RECEIVER MODULE
# ABOUT RECEIVING KEY

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
            #cypher = PKCS1_v1_5.new(pub_key)
            #is_match = cypher.verify(sha_hash, dig_sig_as_bin_str)
            #if is_match:
                #self.send_message("valid")
            #else:
                #self.send_message('invalid')
       

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

