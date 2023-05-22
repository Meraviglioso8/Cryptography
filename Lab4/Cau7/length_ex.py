import hashlib
import hexdump
import struct
import sha256

KEY = b"th1s_1s_K3y"

EXPECTED_KEY_LEN = 32
VALID = b"Extremely Valid Data"
INJECTION = "I'm sussy"

class Sha256Padding:
    def __init__(self):
        self._message_byte_length = 0


    def pad(self, message):
        message_byte_length = self._message_byte_length + len(message)
        message += b'\x80'

        message += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)

        message_bit_length = message_byte_length * 8
        message += struct.pack(b'>Q', message_bit_length)

        return message
    
def attack(originData, originHash, keyLen):

    pad = Sha256Padding()
    tmpStr = ('A' * keyLen).encode()
    attackData = pad.pad(tmpStr + originData)[keyLen:] + INJECTION.encode()

    sha = sha256.Sha256(INJECTION, originHash.encode())
    attackHash = sha.sha256
    
    return attackData, attackHash

def client():
    h = hashlib.new('sha256')
    h.update(KEY)
    h.update(VALID)
    
    return VALID, h.hexdigest()

def server(data, hashValue):
    h = hashlib.new('sha256')
    h.update(KEY + data)

    if (hashValue == h.hexdigest()):
        print("Real Server")
        print("Received data:", data)
        print("Recevied hash:", hashValue)
        print("Calculated Hash", h.hexdigest())
        return True
    else:
        return False



def main():
    print("Real Client")
    originData, originHash = client()
    server(originData, originHash)
    print("            ")
    print("Advesary")
    for keyLen in range(0, EXPECTED_KEY_LEN):
        attackData, attackHash = attack(originData, originHash, keyLen)
        if(server(attackData, attackHash) is True):
            print("Key Length:", keyLen)
            print("LOL you have been hacked")
            break

if __name__ == "__main__":
    main()