import requests
import json
import getopt
import sys, os

'''
Author: Jamie Levy (Gleeda) <jamie@memoryanalysis.net>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version
2 of the License, or (at your option) any later version.

pushtimeline.py: Push timeline information to Kibana
	-h, --help: Print out this message
	-d, --delete [http://localhost:9200/INDEX]: Delete INDEX
	-m, --machine [MACHINE]: Machine identifier
	-u, --url [KIBANA URL]: Default http://localhost:9200
	-f, --file [FILE]: File to read time data from
	-b, --body: File in bodyfile format

'''

url="http://localhost:9200/"
mapping = "{0}allmachines/_mapping/timeline".format(url)
mytype = '{"timeline": {"properties": {"timestamp": {"type":"date","format": "epoch_second"}}}}'

def usage():
    print "pushtimeline.py: Push timeline information to Kibana"
    print "\t-h, --help: Print out this message"
    print "\t-d, --delete [http://localhost:9200/INDEX]: Delete INDEX"
    print "\t-m, --machine [MACHINE]: Machine identifier"
    print "\t-u, --url [KIBANA URL]: Default http://localhost:9200"
    print "\t-f, --file [FILE]: File to read time data from"
    print "\t-b, --body: File in bodyfile format" 

def fixup1(item):
    item = item.replace("\\", "\\\\")
    item = item.replace("\"", "\\\"")
    item = item.replace(":", "\\\\:")
    #item = item.replace("$", "\\\\$")
    return item

def fixtime(stamp):
    if stamp == "-" or int(stamp) == -1:
        return 0
    stamp = stamp if int(stamp) < 2147483647 else 0
    return stamp

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hbu:m:f:d:", ["help", "delete=", "url=", "machine=", "file=", "body"])
    except getopt.GetoptError, err:
        print str(err)
        sys.exit(2)

    file = None
    machine = None
    url="http://localhost:9200/"
    mapping = "{0}allmachines/_mapping/timeline".format(url)
    mytype = '{"timeline": {"properties": {"timestamp": {"type":"date","format": "epoch_second"}}}}'
    body = False
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            return
        if o in ("-b", "--body"):
            body = True
        elif o in ("-u", "--url"):
            url = "{0}".format(a.lower())
        elif o in ("-d", "--delete"):
            r = requests.delete(a.lower())
            print r.content
            return
        elif o in ("-m", "--machine"):
            machine = a.lower()
            url = "{0}{1}".format(url, machine)
            r = requests.put(url)
            mapping = "{0}/_mapping/timeline".format(url)
            url = "{0}/timeline?pretty".format(url)
        elif o in ("-f", "--file"):
            file = a
        else:
            assert False, "unhandled option\n\n"
            return

    if file == None:
        print "You must specify a file!"
        usage()
        return

    if not os.path.isfile(file):
        print "File {0} not found!".format(file)
        usage()
        return

    print "Url", url
    print "Mapping", mapping
    print "Machine", machine
    r = requests.put(mapping, data=mytype)
    print r.content


    f = open(file, "r")
    if not body:
        for payload in f.readlines():
            print payload.strip()
            print json.dumps(payload.strip())
            r = requests.post(url, data=payload.strip())
            print r.content
    else:
        bbrace = "{"
        ebrace = "}"
        for payload in f.readlines():
            print payload.strip()
            things = payload.strip().split("|")
            #header,accessed, modified, mftaltered, creation 
            #things[1], things[-4], things[-3], things[-2], things[-1]
            accessed = fixtime(things[-4]) 
            modified = fixtime(things[-3]) 
            mftaltered = fixtime(things[-2]) 
            creation = fixtime(things[-1]) 
            line1 = "{0}\"machine\": \"{1}\", \"timestamp\": {2}, \"timetype\": \"{3}\", \"event\": \"{4}\", \"message\": \"{5}\"{6}".format(
                bbrace,
                machine,
                modified,
                "modified",
                things[1].split("]")[0] + "]",
                fixup1(things[1]),
                ebrace)
            line2 = "{0}\"machine\": \"{1}\", \"timestamp\": {2}, \"timetype\": \"{3}\", \"event\": \"{4}\", \"message\": \"{5}\"{6}".format(
                bbrace,
                machine,
                accessed,
                "accessed",
                things[1].split("]")[0] + "]",
                fixup1(things[1]),
                ebrace)
            line3 = "{0}\"machine\": \"{1}\", \"timestamp\": {2}, \"timetype\": \"{3}\", \"event\": \"{4}\", \"message\": \"{5}\"{6}".format(
                bbrace,
                machine,
                mftaltered,
                "mftaltered",
                things[1].split("]")[0] + "]",
                fixup1(things[1]),
                ebrace)
            line4 = "{0}\"machine\": \"{1}\", \"timestamp\": {2}, \"timetype\": \"{3}\", \"event\": \"{4}\", \"message\": \"{5}\"{6}".format(
                bbrace,
                machine,
                creation,
                "creation",
                things[1].split("]")[0] + "]",
                fixup1(things[1]),
                ebrace)

            for item in [line1, line2, line3, line4]:
                r = requests.post(url, data=item.strip())
                print r.content



if __name__ == "__main__":
    main()
