#
# Author: Gleeda
# 
# setify.py 
#   takes in a directory of strings files and prints out strings contained in each of them
#

import os, getopt
import sys
import string

sensitive = True

def usage():
    print 'setify.py:'
    print '  - takes in a directory containing strings files for executables and outputs unique strings shared by all exes'
    print '\t-h, --help        : print help message'
    print '\t-d, --directory   : directory with strings files'
    print '\t-i, --insensitive : case insensitive'
    print '\t-o, --output      : output file\n'

def printset(theset, output):
   for item in theset:
        output.write(item + "\n")
 

def process(dir, output):
    list_of_sets = {}
    global sensitive

    for subdir, dirs, files in os.walk(dir):
        for file in files:
            if os.path.exists(dir + "/" + file):
                temp = set([])
                f = open(dir + "/" + file, 'r')
                lines = f.readlines()
                f.close()
                for line in lines:
                    if not sensitive:
                        line = line.lower()
                    line = line.rstrip("\r\n")
                    temp.add(line)
                list_of_sets[file] = temp

    things = list_of_sets.keys()

    if len(things) == 1:
        printset(list_of_sets[things[0]], output)
        return
    elif len(things) >= 2:
        theset = list_of_sets[things[0]] & list_of_sets[things[1]]
    else:
        print "No files found in directory", dir
        return

    for item in list_of_sets:
        if item != things[0] and item != things[1]:
            theset &= list_of_sets[item]

    printset(theset, output)

    

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hio:d:", ["help", "insensitive", "output=", "directory="])
    except getopt.GetoptError, err:
        print str(err)
        sys.exit(-1)
    output = sys.stdout
    dir = None
    global sensitive
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit(2)
        elif o in ("-o", "--output"):
            output = open(a,'w')
        elif o in ("-d", "--directory"):
            dir = a
        elif o in ("-i", "--insensitive"):
            sensitive = False
        else:
            assert False, "unhandled option\n\n"
            sys.exit(-1)

    if dir == None:
        usage()
        sys.exit(-1)

    process(dir, output)

if __name__ == "__main__":
    main()
