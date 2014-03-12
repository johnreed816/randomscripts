#!/usr/bin/python


def main():
    fib = []
    totalSum = 0
    for x in range (1, 4000000):
        if x == 1 or x == 2:
            fib.append(x)
        else:
            if fib[-1] + fib[-2] < 4000000:
                fib.append(fib[-1] + fib[-2])
            else:
                break
        
    for x in range (0, len(fib)):
        if fib[x] % 2 == 0:
            print fib[x] 
            totalSum += fib[x] 
     
    print fib
    print totalSum
         

if __name__ == "__main__":
    main()





