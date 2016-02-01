# Credentials for the remote machine
# so you can install fresponse remotely
REMOTEUSER=
REMOTEPASS=

# IP addresses of remote machines:
# example IPs below, replace with your own:
IPs=(192.168.1.143 192.168.1.134)

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
# All disks, memory, volumes that are mounted:
# This is populated as nodes are discovered
# (do not populate yourself)
RESOURCES=()

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


if [[ $EUID -ne 0 ]]; 
then
   echo "This script must be run as root" 1>&2
   exit -1
fi


if [[ ! -f $EXE ]];
then
   echo "File $EXE does not exist."
   echo "Please copy $EXE into this directory."
   exit -1
fi

if [[ ! -f $INI ]];
then
   echo "File $INI does not exist."
   echo "Please copy $INI into this directory."
   exit -1
fi

function installagent {
    IP=$1
    echo "[*] Installing the F-Response driver and starting its service on $IP"
    mkdir -p /mnt/forensics
    mount -t cifs -o user="$REMOTEUSER%$REMOTEPASS",iocharset=utf8,file_mode=0777,dir_mode=0777 //$IP/c\$ /mnt/forensics

    if [[ $? -ne 0 ]];
    then
        echo "[!!]"
        echo "[!!] Unable to connect to $IP, please check credentials!"
        echo "[!!]"
        IPs=( "${IPs[@]/$IP}" )
        return 1
    fi

    cp $EXE /mnt/forensics/$WIN
    cp $INI /mnt/forensics/$WIN

    net rpc service create $SERV $SERV "%windir%\\$EXE" -I $IP -U "$REMOTEUSER%$REMOTEPASS"
    net rpc service start $SERV -I $IP -U "$REMOTEUSER%$REMOTEPASS"

    umount /mnt/forensics

    sleep 3
    return 0
}


function loginiscsi {
    IP=$1
    echo
    echo
    echo "[*] Finding ISCSI targets for $IP"

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

    RESOURCES+=($MEM\:pmem+$IP)
    RESOURCES+=($MEM\:disk-0+$IP)
    RESOURCES+=($MEM\:vol-c+$IP)

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
}

function waitfordisconnect {
    echo "[*] Use another shell for analysis"
    echo "    Note: you must be root in order to access the devices"
    echo "[*] Press [ENTER] to disconnect....."
    read any
}

function logoutiscsi {
    IP=$1
    echo "[*] Logging out and removing files for $IP...."

    for i in ${RESOURCES[@]}
    do
        item=$( echo $i |cut -d+ -f1 )
        IP1=$( echo $i |cut -d+ -f2 )
        if [ "$IP" == "$IP1" ]; then
            echo "[*] iscsiadm --mode node --targetname $item --portal $IP1 --logout"
            iscsiadm --mode node --targetname $item --portal $IP1 --logout 
            RESOURCES=( "${RESOURCES[@]/$i}" )
        fi
    done
    echo
    echo "[*] iscsiadm --mode discoverydb --type sendtargets --portal $IP --op delete"
    echo
    iscsiadm --mode discoverydb --type sendtargets --portal $IP --op delete
}

function removeagent {
    IP=$1
    echo "[*] Stopping F-Response service and deleting its files on $IP"

    net rpc service stop $SERV -I $IP -U "$REMOTEUSER%$REMOTEPASS"
    net rpc service delete $SERV -I $IP -U "$REMOTEUSER%$REMOTEPASS"
    mkdir -p /mnt/forensics
    mount -t cifs -o user="$REMOTEUSER%$REMOTEPASS",iocharset=utf8,file_mode=0777,dir_mode=0777 //$IP/c\$ /mnt/forensics

    sleep 2

    rm /mnt/forensics/$WIN/$EXE
    rm /mnt/forensics/$WIN/$INI

    umount /mnt/forensics
}


for IP in ${IPs[@]}
do
    installagent $IP
done

for IP in ${IPs[@]}
do
    loginiscsi $IP
done

waitfordisconnect

for IP in ${IPs[@]}
do
    logoutiscsi $IP
    removeagent $IP
done
