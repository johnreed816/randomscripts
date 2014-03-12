#!/usr/bin/python
import math

def Atkin_Sieve(limit):
    results = [2, 3, 5]
    sieve = [False]*limit
    factor =int(math.sqrt(limit))
    for i in range(1, factor):
        for j in range(1, factor):
            n = 4*i**2+j**2
            if (n <= limit) and (n % 12 == 1 or n % 12 == 5):
                sieve[n] = not sieve[n]
            n = 3*i**2+j**2
            if (n <= limit) and (n % 12 == 7):
                sieve[n] = not sieve[n]
            if i < j:
                n = 3*i**2-j**2
                if (n <= limit) and (n % 12 == 11):
                    sieve[n] = not sieve[n]
    for index in range(5, factor):
        if sieve[index]:
            for jndex in range(index**2, limit, index**2):
                sieve[jndex] = False
    for index in range(7, limit):
        if sieve[index]:
            results.append(index)
    return results

def getsum(primes):
    return reduce(lambda q,p: p+q, primes)

if __name__ == "__main__":
    limit = raw_input("Enter the number of primes to calculate: ")
    blah = Atkin_Sieve(int(limit)) 
    print blah[:5]
    print getsum(blah)
