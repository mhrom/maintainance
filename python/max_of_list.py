#!/usr/bin/python

import sys

def main():
    max_number = 0
    for i in range(len(sys.argv[1:])+1):
        for j in range(i+1, len(sys.argv[1:])+1):
            
            if max_number > sys.argv[i] and max_number > sys.argv[j]:
                max_number = max_number
            elif max_number < sys.argv[i] and sys.argv[i] > sys.argv[j]:
                max_numer = sys.argv[i]
            elif sys.argv[j] > sys.argv[i] and max_number < sys.argv[j]:
                max_number = sys.argv[j]
    print max_number
if __name__=="__main__":
    main() 
