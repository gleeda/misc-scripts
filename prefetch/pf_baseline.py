# author: Gleeda
# 
# pf_baseline allows one to quickly find uncommon prefetch files by calculating a list from baseline
#   prefetch names from known paths.  Items that are not in that baseline are printed.
# hashing functions  are taken from Yogesh Khatri's EnScript for prefetch

import ctypes
import getopt, sys, os
import sqlite3

def usage():
    print 'pf_baseline.py:'
    print '  - finds uncommon prefetch files using a base of exes'
    print '\t-h, --help       : Print this help message'
    print '\t-x, --xp         : Use prefetch hashing algorithm for XP/2K3 (Default)'
    print '\t-v, --vista      : Use prefetch hashing algorithm for Vista/2k8/Win7'
    print '\t-d, --database   : EnCase baseline database'
    print '\t                      (or any sqlite3 db with same schema: SELECT path FROM entries WHERE path LIKE \'%exe\')'
    print '\t-l, --location   : Directory of prefetch files'
    print '\t-n, --numvols    : Number of volumes to create baseline for (e.g. -n 3 : harddiskvolume1, harddiskvolume2, harddiskvolume3)'
    print '\t-p, --particular : A particular volume to create the baseline for (e.g. -p 2 : harddiskvolume2)\n'
    print "Example usage:\n\t$ python pf_baseline.py -d baseline.db -v -l /path/to/prefetch/files\n"

class PFBaseline:

    def __init__(self, XP = True, numvolumes = 1):
        self.volume = "\\device\\harddiskvolume"
        self.XP = XP
        self.numvolumes = numvolumes
        self.prefetches = []
        # appending other known files in Windows\Prefetch:
        self.prefetches.append("NTOSBOOT-B00DFAAD.pf")
        self.prefetches.append("Layout.ini")


    def GenOneVolHashes(self, cmds, volume = 1):
        for c in cmds:
            exe = c.split("\\")[-1].upper()
            cmd = self.volume + str(volume) + "\\" + c 
            if self.XP:
                item = "{0}-{1:08X}.pf".format(exe, self.generateXpHash(cmd.upper()))
            else:
                item = "{0}-{1:08X}.pf".format(exe, self.generateVistaHash(cmd.upper()))
            if item not in self.prefetches:
                self.prefetches.append(item)

    def GenAllVolHashes(self, cmds):
        for c in cmds:
            exe = c.split("\\")[-1].upper()
            for i in xrange(1, self.numvolumes + 1):
                cmd = self.volume + str(i) + "\\" + c
                if self.XP:
                    item = "{0}-{1:08X}.pf".format(exe, self.generateXpHash(cmd.upper()))
                else:
                    item = "{0}-{1:08X}.pf".format(exe, self.generateVistaHash(cmd.upper()))
                if item not in self.prefetches:
                    self.prefetches.append(item)

    def generateXpHash(self, cmd):
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

    def generateVistaHash(self, cmd):
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
        opts, args = getopt.getopt(sys.argv[1:], "hvxn:d:p:l:", ["help", "location=", "database=", "numvols=", "particular=", "xp", "vista"])
    except getopt.GetoptError, err:
        print str(err)
        sys.exit(2)

    xp = True
    vol = None
    vols = None
    base = None
    dir = None
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            return
        elif o in ("-x", "--xp"):
            xp = True
        elif o in ("-v", "--vista"):
            xp = False
        elif o in ("-d", "--database"):
            base = a
        elif o in ("-n", "--numvols"):
            vols = a
        elif o in ("-p", "--particular"):
            vol = a
        elif o in ("-l", "--location"):
            dir = a
        else:
            assert False, "unhandled option\n\n"
            return

    if not base:
        print "No database specified!"
        usage()
        return

    if not dir:
        print "No directory of prefetch files specified!"
        usage()
        return

    cmds = []
    rc = sqlite3.connect(base)
    cur = rc.cursor()
    q = "SELECT path FROM entries WHERE path LIKE '%exe'"
    for i in cur.execute(q):
        cmds.append(i[0])
    rc.close()

    if vols != None:
        p = PFBaseline(XP = xp, numvolumes = int(vols))
        p.GenAllVolHashes(cmds = cmds)
    elif vol != None:
        p = PFBaseline(XP = xp)
        p.GenOneVolHashes(cmds = cmds, volume = int(vol))
    else:
        p = PFBaseline(XP = xp)
        p.GenOneVolHashes(cmds = cmds)

    os.chdir(dir)
    for fname in os.listdir(dir):
        if os.path.isfile(os.path.join(dir, fname)):
            if fname not in p.prefetches:
                print fname

if __name__ == "__main__":
    main()
