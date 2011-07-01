# author: Gleeda
# port of hashing functions from Yogesh Khatri's EnScript
#   for prefetch

import ctypes
import getopt, sys

def usage():
    print 'prefetch_hash.py:'
    print '  - generates the name of the prefetch file given a kernel path to the program'
    print '\t-h, --help     : print help message'
    print '\t-p, --path     : kernel path to a program (not case sensitive)'
    print '\t-x, --xp       : print the name of a prefetch file for XP/2K3'
    print '\t-v, --vista    : print the name of a prefetch file for Vista/2k8/Win7\n'
    print "Example usage:\n\t$ python prefetch_hash.py -p '\\device\\harddiskvolume1\\windows\\system32\\notepad.exe' -v"

def generateXpHash(cmd):
    hash = 0 
    uni = unicode(cmd)
    for i in range(len(uni)):
        num = ord(uni[i])
        if (num > 255): 
            hash = ctypes.c_int32(37 * ((37 * hash) + (num / 256)) + (num % 256)).value
        else:
            hash = ctypes.c_int32(37 * ((37 * hash) + num)).value
    hash *= 314159269
    hash = ctypes.c_int32(hash).value
    if hash < 0:
        hash *= -1
    hash %= 1000000007
    return ctypes.c_uint32(hash).value

def generateVistaHash(cmd):
    hash = 314159
    uni = unicode(cmd)
    for i in range(len(uni)):
        num = ord(uni[i])
        if (num > 255):
            hash = ctypes.c_int32(37 * ((37 * hash) + (num / 256)) + (num % 256)).value
        else:
            hash = ctypes.c_int32(37 * ((37 * hash) + num)).value
    return ctypes.c_uint32(hash).value

def main():    
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hvxp:", ["help", "path=", "xp", "vista"])
    except getopt.GetoptError, err:
        print str(err)
        sys.exit(2)

    cmd = None
    xp = False
    vista = False
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit(2)
        elif o in ("-x", "--xp"):
            xp = True
        elif o in ("-v", "--vista"):
            vista = True
        elif o in ("-p", "--path"):
            cmd = a.upper()
        else:
            assert False, "unhandled option\n\n"
            sys.exit(2)

    if cmd == None:
        print "You must enter a path!"
        usage()
        sys.exit(2)

    exe = cmd.split("\\")[-1]

    if xp:
        hash = "%X" % generateXpHash(cmd)
        print exe + "-" + str(hash) + ".pf"
    if vista:
        hash = "%X" % generateVistaHash(cmd)
        print exe + "-" + str(hash) + ".pf"
    if not xp and not vista:
        print "No type of OS specified!"
        usage()

if __name__ == "__main__":
    main()
