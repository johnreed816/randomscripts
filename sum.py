#!/usr/bin/python


def main():
   allNums = [] 
   totalSum = 0
   for x in range(0, 1000):
       if x % 3 == 0 or x % 5 ==0:
           totalSum += x
   print totalSum

if __name__ == "__main__":
    main()
