# Credentials for the remote machine
# so you can install fresponse remotely
LOCALUSER=
LOCALPASS=

#IP Address of remote machine:
IP=

# F-Response Enterprise agent and INI file
# You can change the name of the executable
#  but the INI file should be renamed accordingly too
# These files should be in the same directory as this script
EXE=f-response-ent.exe   
INI=f-response-ent.exe.ini 
# F-Reponse port:
PORT=3260
# F-Response username and password:
FRUSER=
FRPASS=  
# Name of service on remote machine:
SERV=fresponse  
# Location of agent and INI file on remote machine:
WIN=WINDOWS

#######################################################
##  Author: Jamie Levy (Gleeda) <jamie.levy@gmail.com>
##
##  fresponse.bash: F-Response Enterprise Helper Script
##
##   Allows one to install and start the F-Response
##      service from a Linux machine 
##   Also automates the discovery and logging into
##      F-Response nodes
##   This is a quick and dirty script and should
##      be expanded as needed...
##
#######################################################


if [ ! -f $EXE ];
then
   echo "File $EXE does not exist."
   echo "Please copy $EXE into this directory."
   exit
fi

if [ ! -f $INI ];
then
   echo "File $INI does not exist."
   echo "Please copy $INI into this directory."
   exit
fi


echo "[*] Installing the F-Response driver and starting its service"
mkdir -p /mnt/forensics
sudo mount -t cifs -o user="$LOCALUSER%$LOCALPASS",iocharset=utf8,file_mode=0777,dir_mode=0777 //$IP/c\$ /mnt/forensics

sudo cp $EXE /mnt/forensics/$WIN
sudo cp $INI /mnt/forensics/$WIN

net rpc service create $SERV $SERV "%windir%\\$EXE" -I $IP -U "$LOCALUSER%$LOCALPASS"
net rpc service start $SERV -I $IP -U "$LOCALUSER%$LOCALPASS"

umount /mnt/forensics

sleep 3

echo
echo
echo "[*] Finding ISCSI targets"

iscsiadm --mode discoverydb --type sendtargets --portal  $IP --op new 
iscsiadm --mode discoverydb  --type sendtargets --portal $IP --op update --name discovery.sendtargets.auth.username --value $FRUSER
iscsiadm --mode discoverydb --type sendtargets --portal $IP --op update --name discovery.sendtargets.auth.password  --value $FRPASS
MEM=`iscsiadm --mode discoverydb --type sendtargets --portal $IP  --discover|grep pmem$ |awk '{print $2}'|cut -d\: -f1`
iscsiadm --mode discoverydb --type sendtargets --portal $IP  --discover
iscsiadm --mode node --portal  $IP --op update --name node.session.auth.username --value $FRUSER
iscsiadm --mode node --portal  $IP --op update --name node.session.auth.password --value $FRPASS

echo
echo
echo "[*] Logging into $MEM\:pmem , $MEM\:disk-0 and $MEM\:vol-c"

iscsiadm --mode node --targetname $MEM\:pmem --portal $IP --login
iscsiadm --mode node --targetname $MEM\:disk-0 --portal $IP --login
iscsiadm --mode node --targetname $MEM\:vol-c --portal $IP --login

MOUNTDISK=/dev/disk/by-path/ip-$IP:$PORT-iscsi-$MEM\:disk-0-lun-0
MOUNTMEM=/dev/disk/by-path/ip-$IP:$PORT-iscsi-$MEM\:pmem-lun-0
MOUNTVOL=/dev/disk/by-path/ip-$IP:$PORT-iscsi-$MEM\:vol-c-lun-0

sleep 3

echo
echo "The following devices are available:"
echo
echo MEM:
readlink -f $MOUNTMEM
echo
echo "[*] To use Volatility:"
echo "  $ sudo python vol.py -f `readlink -f $MOUNTMEM` --profile=PROFILE PLUGIN"

echo
echo RAW DISK: 
readlink -f $MOUNTDISK
echo
echo "[*] To use sleuthkit: "
echo "  $ sudo mmls `readlink -f $MOUNTDISK`"
echo "[*] For more, see http://wiki.sleuthkit.org/index.php?title=FS_Analysis"

echo
echo VOLUME:
readlink -f $MOUNTVOL
echo
echo "[*] To mount the volume:"
echo "  $ sudo mount -t ntfs -o ro,show_sys_files,hide_hid_files `readlink -f $MOUNTVOL` /mnt/disk/"
echo
echo
echo

echo "[*] Press [ENTER] to disconnect....."

read any

echo "[*] Logging out and removing files...."

for i in $MEM:pmem $MEM:disk-0 $MEM:vol-c
do
    echo "[*] iscsiadm --mode node --targetname $i --portal $IP --logout"
    iscsiadm --mode node --targetname $i --portal $IP --logout 
done
iscsiadm --mode discoverydb --type sendtargets --portal $IP --op delete

echo "[*] Stopping F-Response service and deleting its files"

net rpc service stop $SERV -I $IP -U "$LOCALUSER%$LOCALPASS"

net rpc service delete $SERV -I $IP -U "$LOCALUSER%$LOCALPASS"

mkdir -p /mnt/forensics
sudo mount -t cifs -o user="$LOCALUSER%$LOCALPASS",iocharset=utf8,file_mode=0777,dir_mode=0777 //$IP/c\$ /mnt/forensics

sleep 2

sudo rm /mnt/forensics/$WIN/$EXE
sudo rm /mnt/forensics/$WIN/$INI

sudo umount /mnt/forensics
