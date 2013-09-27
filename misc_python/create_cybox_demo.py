"""
Author: Jamie Levy (gleeda)
email: jamie.levy@gmail.com

Example script to show how to create CybOX observables
You must install python-cybox before using:
    https://github.com/CybOXProject/python-cybox

Many thanks to Ivan Kirillov and Greg Back for answering many questions and bug fixes :-)
"""
import sys  
import base64
from cybox.core import Observables, Observable, Object, ObservableComposition
from cybox import helper
from cybox.objects.process_object import Process, ImageInfo
from cybox.objects.mutex_object import Mutex
from cybox.objects.file_object import File 
from cybox.objects.win_service_object import WinService
from cybox.objects.win_registry_key_object import WinRegistryKey


# this can be changed to an output file
outfd = sys.stdout

# create an Observable object: 
observables_doc = Observables([])

# add some different observables:
# you don't have to use every member and there are other members that are not being utilized here:
observables_doc.add(Process.from_dict({"name": "Process.exe",
                                       "pid": 90,  
                                       "parent_pid": 10,
                                       #"creation_time": "",  
                                       "image_info": {"command_line": "Process.exe /c blah.txt"}}))

observables_doc.add(File.from_dict({"file_name": "file.txt",
                                    "file_extension": "txt",
                                    "file_path": "path\\to\\file.txt"}))
                                    

observables_doc.add(helper.create_ipv4_observable("192.168.1.101"))

observables_doc.add(helper.create_url_observable("somedomain.com"))

observables_doc.add(WinService.from_dict({"service_name": "Service Name",
                                  "display_name": "Service Display name",
                                  "startup_type": "Service type",
                                  "service_status": "Status",
                                  "service_dll": "Somedll.dll",
                                  "started_as": "Start",
                                  "group_name": "Group name",
                                  "startup_command_line": "Commandline"}))

observables_doc.add(WinRegistryKey.from_dict({"hive": "SYSTEM",
                                             "key": "some\\registry\\key",
                                             "number_values": 2,
                                             "values": [{"name": "Something", 
                                                         "datatype": "REG_DWORD", #or whatever it is...
                                                         "data": "Something else"},
                                                        {"name": "Another", 
                                                         "datatype": "REG_BINARY", #or whatever it is...
                                                         "data": base64.b64encode("\x90\x90\x90")}], #binary stuff must be normalized, base64 is the usual
                                             "number_subkeys": 1,
                                             # subkeys have the same members as keys:
                                             "subkeys": [{"key": "SubkeyName", "number_values": 1, 
                                                            "values": [{"name": "SubkeyVal", "datatype": "REG_DWORD", "data": "Subkey val data"}]}]
                                            }))

observables_doc.add(Mutex.from_dict({"name": "Some_MUTEX!!!"}))

# we can also specify conditions:
proc = Process.from_dict({"name": "anotherProcess.exe",
                          "pid": 102,  
                          "parent_pid": 10,
                          "image_info": {"command_line": "anotherProcess.exe /c blahblah.bat"}})
proc.name.condition = "Equals"
proc.image_info.command_line.condition = "Contains"
# we need the same object so we can use the id for the compositions below
obs1 = Observable(proc)
observables_doc.add(obs1)

file = File.from_dict({"file_name": "blah", "file_extension": "bat"})
file.file_name.condition = "Contains"
file.file_extension.condition = "Equals"
obs2 = Observable(file)
observables_doc.add(obs2)

mutex = Mutex.from_dict({"name": "Some_OTHER_MUTEX!!!"})
obs3 = Observable(mutex)
observables_doc.add(obs3)

# to add logic:
# normally you'd probably have logic for all items, but this is just a demo, not reality 
oproc_ref = Observable()
oproc_ref.id_ = None
oproc_ref.idref = obs1.id_

ofile_ref = Observable()
ofile_ref.id_ = None
ofile_ref.idref = obs2.id_

omutex_ref = Observable()
omutex_ref.id_ = None
omutex_ref.idref = obs3.id_

o_comp = Observable(ObservableComposition(operator = "OR"))
o_comp.observable_composition.add(oproc_ref)
o_comp.observable_composition.add(ofile_ref)

o_comp2 = Observable(ObservableComposition(operator = "AND"))
o_comp2.observable_composition.add(omutex_ref)

o_comp.observable_composition.add(o_comp2)

# add our composition to the observables:
observables_doc.add(o_comp)

# output to stdout or file or whatever:
outfd.write(observables_doc.to_xml())

