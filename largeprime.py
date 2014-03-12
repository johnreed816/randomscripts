#!/usr/bin/python


def main():
    primes = []
    i = 2
    while (i > 0):
        if isPrime(i):
            primes.append(i)
        if len(primes) >  10001:
            break
        i += 1
    return primes[6]
  

def isPrime(num):
    i = num / 2
    while ( i > 1 ):
        if num % i == 0 and num != i:
            return False 
        i -= 1
    return True

if __name__ == "__main__":
    solution = main()
    print solution
