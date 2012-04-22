import distorm3
import getopt, sys
import hashlib
import struct

'''
Author: Gleeda

$ python mbr_parser.py -f mbr 
    no frills, prints out to stdout

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version
2 of the License, or (at your option) any later version.

 Using structures defined in File System Forensic Analysis pg 88+
 boot code is from bytes 0-439 in the partition table
 we should dissassemble

 extra partition types taken from Gary Kessler's MBRParser.pl:
    http://www.garykessler.net/software/index.html

'''

PartitionTypes = { 
    0x00:"Empty",
    0x01:"FAT12,CHS",
    0x04:"FAT16 16-32MB,CHS",
    0x05:"Microsoft Extended",
    0x06:"FAT16 32MB,CHS",
    0x07:"NTFS",
    0x0b:"FAT32,CHS",
    0x0c:"FAT32,LBA",
    0x0e:"FAT16, 32MB-2GB,LBA",
    0x0f:"Microsoft Extended, LBA",
    0x11:"Hidden FAT12,CHS",
    0x14:"Hidden FAT16,16-32MB,CHS",
    0x16:"Hidden FAT16,32MB-2GB,CHS",
    0x18:"AST SmartSleep Partition",
    0x1b:"Hidden FAT32,CHS",
    0x1c:"Hidden FAT32,LBA",
    0x1e:"Hidden FAT16,32MB-2GB,LBA",
    0x27:"PQservice",
    0x39:"Plan 9 partition",
    0x3c:"PartitionMagic recovery partition",
    0x42:"Microsoft MBR,Dynamic Disk",
    0x44:"GoBack partition",
    0x51:"Novell",
    0x52:"CP/M",
    0x63:"Unix System V",
    0x64:"PC-ARMOUR protected partition",
    0x82:"Solaris x86 or Linux Swap",
    0x83:"Linux",
    0x84:"Hibernation",
    0x85:"Linux Extended",
    0x86:"NTFS Volume Set",
    0x87:"NTFS Volume Set",
    0x9f:"BSD/OS",
    0xa0:"Hibernation",
    0xa1:"Hibernation",
    0xa5:"FreeBSD",
    0xa6:"OpenBSD",
    0xa8:"Mac OSX",
    0xa9:"NetBSD",
    0xab:"Mac OSX Boot",
    0xaf:"MacOS X HFS",
    0xb7:"BSDI",
    0xb8:"BSDI Swap",
    0xbb:"Boot Wizard hidden",
    0xbe:"Solaris 8 boot partition",
    0xd8:"CP/M-86",
    0xde:"Dell PowerEdge Server utilities (FAT fs)",
    0xdf:"DG/UX virtual disk manager partition",
    0xeb:"BeOS BFS",
    0xee:"EFI GPT Disk",
    0xef:"EFI System Parition",
    0xfb:"VMWare File System",
    0xfc:"VMWare Swap",
}

class PartitionEntry:
    def __init__(self, data):
        self.BootableFlag = struct.unpack("<c", data[:1])[0]
        self.StartCHS0 = struct.unpack("<B", data[1:2])[0]
        self.StartCHS1 = struct.unpack("<B", data[2:3])[0]
        self.StartCHS2 = struct.unpack("<B", data[3:4])[0]
        self.PartitionType = struct.unpack("<c", data[4:5])[0]
        self.EndCHS0 = struct.unpack("<B", data[5:6])[0]
        self.EndCHS1 = struct.unpack("<B", data[6:7])[0]
        self.EndCHS2 = struct.unpack("<B", data[7:8])[0]
        self.StartLBA = struct.unpack("<I", data[8:12])[0]
        self.SizeInSectors = struct.unpack("<i", data[12:16])[0]

class PartitionTable:
    def __init__(self, data):
        self.DiskSignature0 = struct.unpack("<B", data[:1])[0]
        self.DiskSignature1 = struct.unpack("<B", data[1:2])[0]
        self.DiskSignature2 = struct.unpack("<B", data[2:3])[0]
        self.DiskSignature3 = struct.unpack("<B", data[3:4])[0]
        self.Unused = struct.unpack("<H", data[4:6])[0]
        self.Entry0 = PartitionEntry(data[6:22])
        self.Entry1 = PartitionEntry(data[22:38])
        self.Entry2 = PartitionEntry(data[38:54])
        self.Entry3 = PartitionEntry(data[54:70])
        self.Signature = struct.unpack("<H", data[70:72])[0]  

class MBRParser:
    def __init__(self, data):
        self.PartitionTable = PartitionTable(data[440:])
        self.BootCode = data[:440]

    def print_self(self):
        E0 = self.process_entry(self.PartitionTable.Entry0)
        E1 = self.process_entry(self.PartitionTable.Entry1)
        E2 = self.process_entry(self.PartitionTable.Entry2)
        E3 = self.process_entry(self.PartitionTable.Entry3)

        print "Disk signature: {0:02x}-{1:02x}-{2:02x}-{3:02x}\n".format(self.PartitionTable.DiskSignature0, 
            self.PartitionTable.DiskSignature1, 
            self.PartitionTable.DiskSignature2, 
            self.PartitionTable.DiskSignature3)

        h = hashlib.md5()
        h.update(self.BootCode)
        print "Bootcode md5: {0}\n".format(h.hexdigest())
    
        iterable = distorm3.DecodeGenerator(0, self.BootCode, distorm3.Decode16Bits)
        ret = "" 
        for (offset, size, instruction, hexdump) in iterable:
            ret += "%.8x: %-32s %s\n" % (offset, hexdump, instruction)
        print "Bootcode Disassembly:\n\n{0}\n".format(ret)

        print "===== Partition Table #1 =====\n{0}\n".format(E0)
        print "===== Partition Table #2 =====\n{0}\n".format(E1)
        print "===== Partition Table #3 =====\n{0}\n".format(E2)
        print "===== Partition Table #4 =====\n{0}\n".format(E3)

    def get_value(self, char):
        padded = "\x00\x00\x00" + str(char)
        val = int(struct.unpack('>I', padded)[0])
        return val

    def get_type(self, PartitionType):
        try:
            type = PartitionTypes[PartitionType]
        except KeyError:
            type = "Invalid"
        return type

    def get_sector(self, raw_sector):
        return raw_sector % 64

    def get_cylinder(self, raw_sector, raw_cylinder):
        return (raw_sector - self.get_sector(raw_sector)) * 4 + raw_cylinder

    def process_entry(self, entry):
        processed_entry = ""
        bootable = self.get_value(entry.BootableFlag)
        type = self.get_type(self.get_value(entry.PartitionType))
        processed_entry = "Boot flag: {0:#x} {1}\n".format(bootable, "(Bootable)" if bootable == 0x80 else '')
        processed_entry += "Partition type: {0:#x} ({1})\n".format(self.get_value(entry.PartitionType), type)
        processed_entry += "Starting Sector (LBA): {0:#x} ({0})\n".format(entry.StartLBA)
        processed_entry += "Starting CHS: Cylander: {2} Head: {0} Sector: {1}\n".format(entry.StartCHS0,
                    self.get_sector(entry.StartCHS1),
                    self.get_cylinder(entry.StartCHS1, entry.StartCHS2))
        processed_entry += "Ending CHS: Cylander: {2} Head: {0} Sector: {1}\n".format(entry.EndCHS0,
                    self.get_sector(entry.EndCHS1),
                    self.get_cylinder(entry.EndCHS1, entry.EndCHS2))
        processed_entry += "Size in sectors: {0:#x} ({0})\n\n".format(entry.SizeInSectors)
        return processed_entry

def usage():
    print "mbr_parser.py:\n"
    print " -f <mbr>"

def main():
    file = None
    output = sys.stdout
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hf:", ["help", "file="])
    except getopt.GetoptError, err:
        print str(err)
        sys.exit(2)
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit(2)
        elif o in ("-f", "--file"):
            file = open(a,'r')
        else:
            assert False, "unhandled option\n\n"
            sys.exit(2)

    if file == None:
        usage()
        return

    data = file.read(512)
    myMBR = MBRParser(data)
    myMBR.print_self()

if __name__ == "__main__":
    main()
