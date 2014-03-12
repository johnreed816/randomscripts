#!/usr/bin/python


def main():
    return sumofsquares()

def sumofsquares():
    i = 0
    sum = 0
    squareofsum = 0
    while ( i <= 100 ):
        sum += i**2 
        squareofsum += i
        i += 1
    print "sum: ", sum 
    print "squares: ", squareofsum**2 
    return (squareofsum**2 - sum)
        
if __name__ == "__main__":
    solution = main()
    print solution
