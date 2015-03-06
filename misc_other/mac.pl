#!/usr/bin/perl

foreach $filename (@ARGV) {
($dev, $inode, $mode, $nlink, $uid, $gid, $rdev,
 $size, $atime, $mtime, $ctime, $blksize, $blocks) = lstat($filename);
print "$filename (MAC): $mtime,$atime,$ctime\n";
print "$filename (MAC): " . localtime($mtime) . "," . localtime($atime) . "," . localtime($ctime) . "\n"; 
}

