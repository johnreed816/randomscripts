#!/usr/bin/python


def main():
    i = 400
    while ( i < (400 * 20000000000)):
        if isOk(i):
            return i
        print "i: ", i
        i += 20 
        
def isOk(num):
    i = 20
    while ( i > 0):
        if num % i != 0:
            return False 
        i -= 1 
    return True 
        
if __name__ == "__main__":
    solution = main()
    print solution
