import distorm3
import getopt, sys
import hashlib

'''
Author: Gleeda

$ python mbr_bootcode_disassembler.py -f mbr -o mbr_dis.txt
    no frills just gives you the md5 and disassembly of the bootcode for an MBR
'''

def usage():
    print "mbr_bootcode_disassembler.py:\n"
    print " -f <mbr>"
    print " -o <output_file> (optional)\n"

def main():
    file = None
    output = sys.stdout
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hf:o:", ["help", "file=", "output="])
    except getopt.GetoptError, err:
        print str(err)
        sys.exit(2)
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit(2)
        elif o in ("-f", "--file"):
            file = open(a,'r')
        elif o in ("-o", "--output"):
            output = open(a, 'w')
        else:
            assert False, "unhandled option\n\n"
            sys.exit(2)

    if file == None:
        usage()
        return

    data = file.read(440)
    h = hashlib.md5()
    h.update(data)
    iterable = distorm3.DecodeGenerator(0, data, distorm3.Decode32Bits)
    ret = ""  
    for (offset, size, instruction, hexdump) in iterable:
        ret += "%.8x: %-32s %s\n" % (offset, hexdump, instruction)
    output.write("md5 of bootcode: " + h.hexdigest() + "\n")
    output.write(ret)

if __name__ == "__main__":
    main()
