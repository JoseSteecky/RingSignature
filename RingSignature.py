import random
import hashlib
import base64
import array
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash import SHA1
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Utils import  bytesWithPadding
from Crypto.Random import get_random_bytes
from array import *


class RingSignature:

   # def ringSign(self, message, nonSignerPublickeys, signerKeyPair):
       # return self.ringSign([ord(char) for char in message], nonSignerPublickeys, signerKeyPair)

    def ringSign(self, message, nonSignerPublickeys, signerKeyPair):
        signerPubK = signerKeyPair[0]
        publicKeys  = nonSignerPublickeys

        publicKeys.append(signerPubK)

        random.shuffle(publicKeys)
        signerIndex = publicKeys.index(signerPubK)
        print('signer_index: '+str(signerIndex))
        #0. Choose a moduli for all the calculations that is sufficiently great
        commonModulus = self.commonB(publicKeys)

        #1.Compute the key as k = h(m)
        k = self.calculateDigest(message)

        #2 Pick a random glue value
        glue = random.getrandbits(commonModulus.bit_length())

        #3 pick random values x_i for the non_signers and compute y_i
        xValues = list(map(lambda x: random.getrandbits(commonModulus.bit_length()), publicKeys))

        yValues =  list(map(lambda x: self.g(x, publicKeys[xValues.index(x)] , commonModulus) if xValues.index(x) != signerIndex else None, xValues))

        #4 Solve the ring equation for y_ of the signer Ck,v(y1,...,yn)=glue
        yS = self.solve(yValues, k, glue, commonModulus)

        #5Invert the signer's trap-door permutation
        xValues[signerIndex] = self.gInverse(yS, signerKeyPair)

        return {'publicKeys':publicKeys, 'glue': glue, 'xValues': xValues}

    #Returns: '2^b-1' where b is greater than the width of the greatest 'n_i' and multiple of the AES block size
    def commonB(self, publicKeys):
        nMax = 0
        for pk in publicKeys:
            if pk['n'] > nMax:
                nMax = pk['n']

        sufficientBits = nMax.bit_length()+160
        if(sufficientBits % 128 >0):
            sufficientBits +=128 - (sufficientBits %128)
        return pow(2, sufficientBits) -1

    #Returns g(x) = q*n + f(r), where x = q*n+r and f(r) is the RSA encryption operation r^e mod n
    def g(self, x, publicKey, commonModulus):
        q = x//publicKey['n']

        result = x
        if(q + 1)*publicKey['n'] <= commonModulus:
            r = x - q*publicKey['n']

            #key=e

            fr = pow(r, publicKey['key'], publicKey['n'])
            result = q*publicKey['n']+fr
        return result

    def gInverse(self, y, keyPair):
        pub = keyPair[0]
        priv = keyPair[1]

        q = y//pub['n']


        fr = y -q*pub['n']
        #key=d
        r = pow(fr, priv['key'], pub['n'])

        return q*pub['n']+r

        '''      def encrypt(self, message, key):
        if(len(message) %16 == 0):
            aes  '''

    #def ringSigVerity(self, message, signature):
       #return self.ringSigVerify([ord(char) for char in message] , signature)

    def ringSigVerify(self, message, signature):
        if(len(signature['publicKeys']) == len(signature['xValues'])):
            #1
            commonModulus = self.commonB(signature['publicKeys'])
            pubkeys= signature['publicKeys']
            xValues =  signature['xValues']
            yValue =  list(map(lambda x: self.g(x, pubkeys[xValues.index(x)], commonModulus), xValues))

            #2
            k = self.calculateDigest(message)

            #3
            result =  self.C(yValue, k, signature['glue'], commonModulus)
            print('signature_verifier')
            print(result)

            return  result == signature['glue']
        else:
            return False

    def calculateDigest(self, message):
        m = hashlib.sha256()
        m.update(message.encode("utf-8"))
        return  m.digest()



    def encrypt(self, key, source):
        #key = self.calculateDigest(key)  # use SHA-256 over our key to get a proper-sized AES key
        #key = get_random_bytes(16)
        #encryptor = AES.new(key, AES.MODE_CBC)
        # ct_bytes = encryptor.encrypt(pad(source, AES.block_size))
        #return ct_bytes

        obj = AES.new(key, AES.MODE_CBC, 'This is an IV456'.encode("utf8"))

        #return obj.encrypt(pad(source, AES.block_size))
        return obj.encrypt(source)


    def decrypt(self, key, source):
        #key = self.calculateDigest(key)  # use SHA-256 over our key to get a proper-sized AES key
        #key = get_random_bytes(16)
        #decryptor = AES.new(key, AES.MODE_CBC)
        #return  unpad(decryptor.decrypt(source), AES.block_size)
        obj = AES.new(key, AES.MODE_CBC, 'This is an IV456'.encode("utf8"))
        #message = "The answer is no".encode("utf8")
        #return unpad(obj.decrypt(source), AES.block_size)
        return obj.decrypt(source)



    def C(self, yValues, k, glue, commonModulus):
        result = glue

        for y in yValues:
            plaintext = y^result

            #print(y)
            result = self.encrypt(k, bytesWithPadding(plaintext, commonModulus))
            #result = unpad(result, AES.block_size)
            result = int.from_bytes(result, "big")

        return result

    def solve(self, yValue, k, glue, commonModulus):
        remainingArguments = yValue
        temp = glue
        while len(remainingArguments) != 0:

            temp = self.decrypt(k, bytesWithPadding(temp, commonModulus))
            temp = int.from_bytes(temp, "big")
            nextArgument = remainingArguments.pop(len(remainingArguments) - 1)

            if nextArgument:
                temp ^=nextArgument

            else:
                #y_i of a non-signer

                temp ^= self.C(remainingArguments, k, glue, commonModulus)

                break
        return temp


