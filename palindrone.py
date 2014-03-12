#!/usr/bin/python



def main():
    solution = 0
    first = 999
    i = 999
    while (first > 99):
        while (i > 99):
            prod = i * first
            if len(str(prod)) % 2 == 0:
                if isPalindrome(prod):
                    if solution < prod:
                            solution = prod
            i -= 1 
        first -= 1
        i = 999
    return solution

def isPalindrome(num):
    return str(num) == str(num)[::-1]

if __name__ == "__main__":
    answer = main()
    print answer
