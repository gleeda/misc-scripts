import sys
from Registry import Registry


reg = Registry.Registry(sys.argv[1])
k = sys.argv[2]

reg_keys1 = []

def rec(key, reg_keys1):
    reg_keys1.append(key)
    
    for subkey in key.subkeys():
        rec(subkey, reg_keys1)


f = sys.stdout 
rec(reg.root(), reg_keys1)
def process_key(thekey, reg_keys1):
    for key in reg_keys1:
        if key.path().lower().endswith(thekey.lower()): 
            f.write("*"*72 + "\n")
            f.write(key.path().lower())
            for value in key.values():
                f.write("\nVALUENAME: ")
                f.write(value.name())
                f.write("\nVALUE: ")
                try:
                    print value.value()
                except:
                    item = value.value()
                    v = ''.join([str(c) for c in item if (ord(c) > 31 or ord(c) == 9) and ord(c) <= 126])
                    print v.decode("ascii", "ignore")

            f.write("\nSubkeys: \n")
            for subkey in key.subkeys():
                f.write(subkey.path() + "\n")
            f.write("*"*72 + "\n")


print "Processing", sys.argv[1]
process_key(k, reg_keys1)
