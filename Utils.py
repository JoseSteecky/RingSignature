import random


def isPrime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False

    # find r and s
    s = 0
    r = num - 1
    while r & 1 == 0:
        s += 1
        r //= 2
    # do k tests
    k = 128
    for _ in range(k):
        a = random.randrange(2, num - 1)
        x = pow(a, r, num)
        if x != 1 and x != num - 1:
            j = 1
            while j < s and x != num - 1:
                x = pow(x, 2, num)
                if x == 1:
                    return False
                j += 1
            if x != num - 1:
                return False
    return True

def generatePrimeNumber(length):
    v = random.getrandbits(128)
    while not isPrime(v):
        v = random.getrandbits(length)

    return v;

def bytesWithPadding(num, commonBModule):
    numByte = (num.bit_length()+7)//8
    #commonBLength = (commonBModule.bit_length()+7)//8

   # bytes = num.to_bytes(numByte,'big')

    #paddingBytes = commonBLength - numByte

    #print(paddingBytes)

    #padding = paddingBytes.to_bytes(paddingBytes  , 'big')
    padding = num.to_bytes(numByte, 'big')
    #return padding + bytes
    return padding