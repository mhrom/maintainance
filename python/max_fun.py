#!/usr/bin/python

"""The max function to compare two numbers and return bigger one"""

import sys

def main():
    x = sys.argv[1]
    y = sys.argv[2]
    if x > y:
        print x
    elif x < y:
        print y    

if __name__=="__main__":
    main()
