
def convertToBites(string):

    en=string.encode()
    arr=[]
    for i in en:
        arr.append(i)
    return arr

def wordConverter(arrayOfElems):

    collided=0
    for elem in arrayOfElems:
      collided=collided*(2**8)+elem
    return collided

def Lengthwith64bit(Length):

    arr=[0 for x in range(64)]
    inbits=bin(Length)[2:]
    if len(inbits)>2**64:
        raise ValueError('value is bigger than 2**64')
    i=len(inbits)-1
    while i>=0:
        arr[63-i]=inbits[len(inbits)-1-i]
        i-=1

    asBin=""
    asHex=[]
    for j in range(64):
        if (j+1)%8!=0:
            asBin+=str(arr[j])
        else:
            asBin+=str(arr[j])
            asHex.append(asBin)
            asBin=""
    asDec=[]
    for string in asHex:
        asDec.append(int(string,2))
    return asDec


block_size = 64
digest_size = 32

def CH(x,y,z):
    return (x & y ^( (~x) & z ) )

def MAJ( x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def ROTR(n,x):
    try:
        return (x>>n) | (x<<(32-n)) & 0xFFFFFFFF 
    except:
        raise ValueError( 'n should be less than 32 in sha256 for RotateRight %s()'%(n))

def SHR(n,x):
    try:
        return (x>>n)
    except:
        raise ValueError('n should be less than 32 in sha256 for RotateRight %s()'%(n))

def BSIG0(x):
    return ROTR(2,x) ^ROTR(13,x)^ROTR(22,x)

def BSIG1(x):
    return ROTR(6,x) ^ROTR(11,x)^ROTR(25,x)

def SSIG0(x):
    return ROTR(7,x) ^ROTR(18,x)^SHR(3,x)

def SSIG1(x):
    return ROTR(17,x) ^ROTR(19,x)^SHR(10,x)



class Sha256:
 

    def __init__(self, message, originHash=None, salt=None):
        if message is not None:
            if type(message) is not str:
                raise TypeError('%s() argument 1 must be string, not %s' % (self.__class__.__name__, type(message).__name__))
    

        self._K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

  

        self.initialHashValues = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
 
            

        if(originHash is not None):
            import io
            originHash = io.BytesIO(originHash)
            for idx in range(0, 8):
                self.initialHashValues[idx] = int(originHash.read(8), 16)
            self._firstBlockLen = 512
        

        padded=self.padding(message,salt)
        parsed=self.parsing(padded)


        tmp = ''
        for idx in range(0, 8):
            tmp += self.hash(parsed)[idx][2:]
        self.sha256 = tmp


    def padding(self, message=None, salt=None):
        """

        """
        if len(message)>=(2**64):
            raise ValueError('for padding, message length needs to be less than 2**64')
        
        if salt is not None:
          message=salt+message
        bites=convertToBites(message)
        Length=len(bites)*8 
        bites.append(int('10000000',2))
        while (len(bites)*8)%512 !=448:
            bites.append(0)
       
        LenghtArray=Lengthwith64bit(Length + self._firstBlockLen)
        for i in LenghtArray:
            bites.append(i)
      
        return bites

    def parsing(self,message):
       
        width=int(512/32) 
        height= int((len(message)*8)/512)
        Matrix = [[0 for x in range(width)] for y in range(height)] 
        for column in range(len(Matrix)):
            for word in range(len(Matrix[column])):
              first=(column*16+word)*4
              Matrix[column][word]=wordConverter( [ message[first], message[first+1], message[first+2], message[first+3] ] )
       
        return Matrix

    ###         Hash Computation           ###

    def hash(self, preprocessed):
 
        H=self.initialHashValues.copy()
        messageBlocks=[]
        for M in range(len(preprocessed)): 
            W=[0 for words in range(64)]
            for i in range(len(W)):
                if i <16:   
                    W[i]=preprocessed[M][i]
                else:   
                    W[i]=SSIG1(W[i-2]) + W[i-7] + SSIG0(W[i-15]) + W[i-16] & 0xFFFFFFFF
            
            a=  H[ 0 ]
            b=  H[ 1 ]
            c=  H[ 2 ]
            d=  H[ 3 ]
            e=  H[ 4 ]
            f=  H[ 5 ]
            g=  H[ 6 ]
            h=  H[ 7 ]

            for t in range(64):
                T1 = h + BSIG1(e) + CH(e,f,g) + self._K[t] + W[t]
                T2 = BSIG0(a) + MAJ(a,b,c)
                h = g
                g = f
                f = e
                e = d + T1  & 0xFFFFFFFF
                d = c
                c = b
                b = a
                a = T1 + T2  & 0xFFFFFFFF  

               
            H[ 0 ]= a + H[ 0 ] &0xFFFFFFFF  
            H[ 1 ]= b + H[ 1 ] &0xFFFFFFFF  
            H[ 2 ]= c + H[ 2 ] &0xFFFFFFFF  
            H[ 3 ]= d + H[ 3 ] &0xFFFFFFFF
            H[ 4 ]= e + H[ 4 ] &0xFFFFFFFF
            H[ 5 ]= f + H[ 5 ] &0xFFFFFFFF
            H[ 6 ]= g + H[ 6 ] &0xFFFFFFFF
            H[ 7 ]= h + H[ 7 ] &0xFFFFFFFF

            messageBlocks.append(H.copy())
        lastHash=messageBlocks[len(messageBlocks)-1]
        asHex=[0 for i in range(len(lastHash))]
        for e in range(len(lastHash)):
            asHex[e]=hex(lastHash[e]) 
        return asHex
