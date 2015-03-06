#!/usr/bin/python
# Author:  Gleeda
#
# collect.py
# 
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; either version
#2 of the License, or (at your option) any later version.
#

import shutil, errno
import getopt, sys, os

allowable = [
    ".dll", 
    ".sys",
    ".exe",
    ".scr",
    ".drv",
]

def usage():
    print "collect.py:"
    print "  - collects files specified in a text file) from one 'disk' to another"
    print "\t-h, --help      : Print this help message"
    print "\t-s, --source    : Source folder/mount point"
    print "\t-t, --target    : Target folder for collected files (must be absolute and non-existent before running)"
    print "\t-f, --files     : List of files to collect"
    print "\t-d, --driverloc : Location of pathless drivers to cut down on runtime\n"
    print "\t-a, --allfiles  : Collect all files and not just those in allowable extensions (off by default)\n"
    print "Example usage:\n   $ python collect.py -s /path/to/source -t /path/to/target -f /path/to/filelist.txt"

def rreplace(s, old, new, occurrence):
    li = s.rsplit(old, occurrence)
    return new.join(li)

def GetAvailable(dst, fname):
    '''
    Since some modules are listed without full paths, we'll try to find
    and available file name.  Hopefully there aren't any more than 20 
    modules with the same name... nah...
    '''
    if os.path.exists(os.path.join(dst, fname)):
        for i in range(1, 20):
            if not os.path.exists(os.path.join(dst, fname + "." + str(i))):
                return fname + "." + str(i)
        return fname + ".past_threshold"
    else:
        return fname

def ProcessPathlessFiles(src, dst, files):
    subdirlist = []
    os.chdir(src)
    for fname in os.listdir(src):
        if fname.lower() in files and os.path.isfile(os.path.join(src, fname)):
            thefile = os.path.join(src, fname)
            print "Copying " + thefile + " to " + dst
            dstfile = GetAvailable(dst, fname) 
            shutil.copy2(thefile, os.path.join(dst, dstfile))
        elif os.path.isdir(os.path.join(src, fname)):
            subdirlist.append(os.path.join(src, fname))
    for subdir in subdirlist:
        ProcessPathlessFiles(subdir, dst, files)

def GetSelectTypeFiles(src, dst):
    subdirlist = []
    os.chdir(src)
    for fname in os.listdir(src):
        if os.path.isfile(os.path.join(src, fname)) and os.path.splitext(fname.lower())[1] in allowable:
            thefile = os.path.join(src, fname)
            print "Copying " + thefile + " to " + dst 
            dstfile = GetAvailable(dst, fname) 
            shutil.copy2(thefile, os.path.join(dst, dstfile))
        elif os.path.isdir(os.path.join(src, fname)):
            subdirlist.append(os.path.join(src, fname))
    for subdir in subdirlist:
        ProcessPathlessFiles(subdir, dst, files)

def main():    
    try:
        opts, args = getopt.getopt(sys.argv[1:], "has:t:f:d:", ["help", "allfiles", "source=", "target=", "files=", "driverloc="])
    except getopt.GetoptError, err:
        print str(err)
        sys.exit(2)

    source = None
    target = None
    files = None
    drivers = None
    all = False 

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            return
        elif o in ("-s", "--source"):
            source = a
        elif o in ("-t", "--target"):
            target = a
        elif o in ("-f", "--files"):
            files = a
        elif o in ("-d", "--driverloc"):
            drivers = a
        elif o in ("-a", "--allfiles"):
            all = True
        else:
            assert False, "unhandled option\n\n"
            return

    if source == None or target == None or files == None:
        print "You must specify source, target and file list!"
        usage()
        return

    f = open(files, "r")
    items = []
    for line in f.readlines():
        l = line.replace("\n", "")
        src = source + "/" + l
        print src, target + "/" + l
        if all and os.path.isdir(src):
            try:
                shutil.copytree(src, target + "/" + l)
                print "Copied " + src + " to " + target 
            except OSError:
                print "Target directory must be empty!"
                return
        elif os.path.isdir(src):
            GetSelectTypeFiles(src, dst)        
        elif os.path.isfile(src):
            thefile = l.split("/")[-1]
            thepath = target + "/" +  rreplace(l, thefile, '', 1)
            try:
                os.makedirs(thepath)
            except OSError as exc: 
                if exc.errno == errno.EEXIST:
                    pass
                else: raise
            try:
                shutil.copy2(src, target + "/" + l)
                print "Copied file " + src + " to " + target
            except : #OSError:
                print "ERROR copying " + src + " to " + target + "/" + l
                return
        else:
            items.append(l)

    if len(items) > 0:
        if drivers != None:
            if os.path.isdir(drivers):
                source = drivers
        os.mkdir(target + "/drivers")
        ProcessPathlessFiles(source, target + "/drivers", items)

if __name__ == "__main__":
    main()
