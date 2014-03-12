#!/usr/bin/python
import random


def mergesort(list):
    print list
    if len(list) <= 1:
        return list
    middle = len(list) / 2 
    left = list[:middle] 
    right = list[middle:] 
    left = mergesort(left)
    right = mergesort(right)
    return merge(left, right)

def merge(lista, listb):
    result = []
    li, ri = 0, 0
    while li < len(lista) and ri < len(listb): 
        if lista[li] <= listb[ri]:
            result.append(lista[li])
            li += 1
        else:
            result.append(listb[ri])
            ri += 1
    if lista:
        result += lista[li:]
    if listb:
        result += listb[ri:]
   
    return result 

def generateList(num):
    randNum = random.randrange(1, num)
    return str(randNum) 

if __name__ == "__main__":
    num = int(raw_input("Enter number of elements to sort: "))
    maxNum = '9' * num 
    list = generateList(int(maxNum))
    sorted = mergesort(list)
    print "Sorted: ", sorted
