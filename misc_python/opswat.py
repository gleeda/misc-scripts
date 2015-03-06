#!/usr/bin/python
#Author: Gleeda
#
#opswat.py
#    takes in a file or directory of files to upload to opswat and prints output
#    post_multipart, encode_multipart_formdata and get_content_type taken from MHL's avsubmit.py
#
import sys, os, getopt
import urllib, urllib2, urlparse
import json 
import httplib, mimetypes
import time
import sqlite3

# change these:
selector = "http://10.xxx.xxx.xxx/opswat_scan.php"
host = "10.xxx.xxx.xxx"
DBNAME = None

def usage():
    print 'opswat.py:'
    print '  - takes in a file or directory of files to upload to opswat and prints output'
    print '\t-h, --help        : print help message'
    print '\t-d, --directory   : directory with files to upload to opswat'
    print '\t-f, --file        : file to upload to opswat'
    print '\t-q, --db          : sqlite3 output file'
    print '\t-o, --output      : output file\n'

def init(DBNAME):
    if DBNAME == None:
        print "can't initialize DB!"
        return
         
    conn = sqlite3.connect(DBNAME)
    cur = conn.cursor()
    try:    
        cur.execute("select * from opswat")
    except sqlite3.OperationalError:
        cur.executescript(
        '''
        CREATE TABLE opswat (
            id INTEGER PRIMARY KEY, 
            artifact TEXT, 
            file TEXT, 
            md5 TEXT, 
            sha1 TEXT,  
            start TEXT, 
            end TEXT, 
            threat TEXT
        );    
        ''')
        conn.commit()
    try:        
        cur.execute("select * from opswat_avscans")
    except sqlite3.OperationalError:
        cur.executescript(
        ''' 
        CREATE TABLE opswat_avscans (
            id INTEGER PRIMARY KEY, 
            oid INTEGER, 
            avname TEXT, 
            version TEXT, 
            versiondate TEXT, 
            scanresult TEXT, 
            threat TEXT, 
            avdefsignature TEXT, 
            avdefversion TEXT
        );
        ''')
        conn.commit()
    try:
        cur.execute("select * from artifacts")
    except sqlite3.OperationalError:
        cur.executescript(
        ''' 
        CREATE TABLE artifacts (
            id          INTEGER PRIMARY KEY,
            artifact    TEXT,
            file        TEXT,
            source      TEXT
        );
        ''')
    conn.close()


def post_multipart(host, selector, fields, files):
    """ 
    Post fields and files to an http host as multipart/form-data.
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return the server's response page.
    """
    content_type, body = encode_multipart_formdata(fields, files)
    h = httplib.HTTP(host)
    h.putrequest('POST', selector)
    h.putheader('content-type', content_type)
    h.putheader('content-length', str(len(body)))
    h.endheaders()
    h.send(body)
    errcode, errmsg, headers = h.getreply()
    return h.file.read()

def encode_multipart_formdata(fields, files):
    """ 
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return (content_type, body) ready for httplib.HTTP instance
    """
    BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
    CRLF = '\r\n'
    L = []
    for (key, value) in fields:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
        L.append('Content-Type: %s' % get_content_type(filename))
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body

def get_content_type(filename):
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'


def process(outfd, file_to_send):
    global DBNAME
    if DBNAME != None:
        return process_sql(outfd, file_to_send)
    f = open(file_to_send, "r")
    file_contents = f.read()
    f.close()

    files = [("file", os.path.basename(file_to_send), file_contents)]
    fields = [("uploadedFile", file_to_send), ("filename", os.path.basename(file_to_send))]

    json = post_multipart(host, selector, fields, files)

    if json.find("suspiciousfile") == -1: 
        print "Unable to submit sample"
        print json
        return -1

    jsondict = simplejson.loads(json)
    for key, val in jsondict.items():
        outfd.write("*" * 72 + "\n")
        outfd.write("{0:30} {1}\n".format("Filename:", os.path.basename(file_to_send)))
        outfd.write("{0:30} {1}\n".format("md5:", val['md5']))
        outfd.write("{0:30} {1}\n".format("sha1:", val['sha1']))
        outfd.write("{0:30} {1}\n".format("Start Time:", val['starttime']))
        outfd.write("{0:30} {1}\n".format("End Time:", val['endtime']))
        outfd.write("{0:30} {1}\n".format("Final Result:", val['finalresult']))
        if val['finalthreatfound'] == "":
            val['finalthreatfound'] = "None"
        outfd.write("{0:30} {1}\n".format("Final Threat Found:", val['finalthreatfound']))
        outfd.write("*" * 72 + "\n")
        if val['finalthreatfound'] == "None":
            continue 
        for item in val['avresults']:
            outfd.write("{0:30} {1}\n".format("AV Name:", item['avname'] + " " + item['avversion'] + " " + item['avdefversiondate']))
            if item['scanresult'] == 'Failed':
                item['scanresult'] = item['scanresult'].upper()
            outfd.write("{0:30} {1}\n".format("Scan Result:", item['scanresult']))
            if item['threatsfound'] == "":
                item['threatsfound'] = "None"
            else:
                item['threatsfound'] += "  [!!]"
            outfd.write("{0:30} {1}\n".format("Threats Found:", item['threatsfound']))
            outfd.write("{0:30} {1}\n".format("AV DefSignature/DefVersion:", item['avdefsignature'] + "/" + item['avdefversion']))
            outfd.write("-" * 72 + "\n")
        outfd.write("\n\n")
    return 0

def process_sql(outfd, file_to_send):
    global DBNAME
    conn = sqlite3.connect(DBNAME)
    cur = conn.cursor()

    f = open(file_to_send, "r")
    file_contents = f.read()
    f.close()

    files = [("file", os.path.basename(file_to_send), file_contents)]
    fields = [("uploadedFile", file_to_send), ("filename", os.path.basename(file_to_send))]

    json = post_multipart(host, selector, fields, files)

    if json.find("suspiciousfile") == -1:
        print "Unable to submit sample"
        print json
        conn.close()
        return -1

    jsondict = simplejson.loads(json)
    for key, val in jsondict.items():
        outfd.write("*" * 72 + "\n")
        outfd.write("{0:30} {1}\n".format("Filename:", os.path.basename(file_to_send)))
        outfd.write("{0:30} {1}\n".format("Final Result:", val['finalresult']))
        if val['finalthreatfound'] == "": 
            val['finalthreatfound'] = "None"
        outfd.write("{0:30} {1}\n".format("Final Threat Found:", val['finalthreatfound']))

        cur.execute("SELECT COUNT(*) FROM opswat WHERE md5 = ?", [val['md5']])
        count = cur.fetchone()[0]
        if count > 0:
            outfd.write("Sample {0} already exists in DB... not dumped\n".format(val['md5']))
            outfd.write("*" * 72 + "\n")
            continue
        outfd.write("*" * 72 + "\n")

        cur.execute("INSERT INTO opswat VALUES(null, ?,?,?,?,?,?,?)", ("", os.path.basename(file_to_send), 
                    val['md5'], val['sha1'], val['starttime'], val['endtime'], val['finalthreatfound']))
        conn.commit()
        cur.execute("SELECT id FROM opswat WHERE md5 = ?", [val['md5']])
        id = cur.fetchone()[0]

        if val['finalthreatfound'] == "None":
            continue

        cur.execute("SELECT count(*) FROM artifacts WHERE file LIKE ?", [os.path.basename(file_to_send)])
        count = cur.fetchone()[0]
        if count == 0:
            try:
                if os.path.basename(file_to_send).find(".exe") != -1 and q[0].find(".dmp") == -1: 
                    cur.execute("SELECT pname FROM procdump WHERE dump_file = ?", [os.path.basename(file_to_send)])
                    artifact = "Executable: " + cur.fetchone()[0]
                elif os.path.basename(file_to_send).find(".dll") != -1: 
                    cur.execute("SELECT path FROM dlldump WHERE dump_file = ?", [os.path.basename(file_to_send)])
                    artifact = "DLL: " + cur.fetchone()[0]
                elif os.path.basename(file_to_send).find(".dmp") != -1: 
                    cur.execute("SELECT pname FROM vaddump WHERE dump_file like ?", [os.path.basename(file_to_send)])
                    artifact = "Vaddump from process: " + cur.fetchone()[0]
                else:
                    cur.execute("SELECT name FROM moddump WHERE dump_file = ?", [os.path.basename(file_to_send)])
                    artifact = "Module: " + cur.fetchone()[0]
                cur.execute("INSERT INTO artifacts VALUES(null,?,?,?)", (artifact, os.path.basename(file_to_send), "opswat"))
                conn.commit()
            except:
                pass

        for item in val['avresults']:
            if item['scanresult'] == 'Failed':
                item['scanresult'] = item['scanresult'].upper()
            if item['threatsfound'] == "":
                item['threatsfound'] = "None"
            cur.execute("INSERT INTO opswat_avscans VALUES(null, ?,?,?,?,?,?,?,?)", (id, item['avname'], item['avversion'], item['avdefversiondate'],
                        item['scanresult'], item['threatsfound'], item['avdefsignature'], item['avdefversion']))
            conn.commit()

        outfd.write("*" * 72 + "\n\n")
    conn.close()
    return 0


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hf:d:o:q:", ["help", "file=", "output=", "directory=", "db="])
    except getopt.GetoptError, err:
        print str(err)
        sys.exit(2)

    file_to_send = None
    dir = None
    outfd = sys.stdout
    global DBNAME

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit(2)
        elif o in ("-f", "--file"):
            file_to_send = a 
        elif o in ("-d", "--directory"):
            dir = a 
        elif o in ("-o", "--output"):
            outfd = open(a,'w')
        elif o in ("-q", "--db"):
            DBNAME = a
        else:
            assert False, "unhandled option\n\n"
            usage()
            return

    if DBNAME != None:
        init(DBNAME)
            

    if dir != None:
        if not os.path.exists(dir):
            print "Directory " + dir + " not found!\n"
            usage()
            return
        elif not os.path.isdir(dir):
            print dir + " is not a directory!\n"
            usage()
            return
        for subdir, dirs, files in os.walk(dir):
            for file in files:
                if os.path.exists(dir + "/" + file):
                    print "Sending " + dir + "/" + file + "....."
                    status = process(outfd, dir + "/" + file)
                    if status == -1:
                        #we're only gonna give each file 1 extra try...
                        print "Got an error, sleeping it off before trying again..."
                        time.sleep(10)
                        print "Awake - resending file " + dir + "/" + file
                        if process(outfd, dir + "/" + file):
                            print "Another failure, try again later..."
        return

    if file_to_send == None:
        print "You must specify a file or directory of files to send to opswat!\n"
        usage()
        return
    elif not os.path.exists(file_to_send):  
        print "File " + file_to_send + " not found!\n"
        usage()
        return
    elif os.path.isdir(file_to_send):
        print "File " + file_to_send + " is a directory, not a file\n"
        usage()
        return

    status = process(outfd, file_to_send)
    if status == -1:
        print "Got an error, sleeping it off before trying again..."
        time.sleep(5)
        print "Awake - resending file " + file_to_send
        if process(outfd, file_to_send):
            print "Another failure, try again later..."

if __name__ == "__main__":
    main()

