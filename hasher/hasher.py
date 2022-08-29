import glob
import json
import pefile 

def hash_function(str):
    ret = 0
    PRIME_BASE = 17
    PRIME_MOD  = 1001369
    
    for i in range(len(str)):
        ret *= PRIME_BASE
        ret += ord(str[i])
        ret %= PRIME_MOD

    return hex(ret)


def main():
    modules = {}

    for dll in glob.glob(r'C:\Windows\System32\user32.dll'):
        
            pe = pefile.PE(dll)

            module_name = dll.split('\\')[-1]

            modules[module_name] = {}
            modules[module_name]['hash'] = hash_function(module_name)
            modules[module_name]['export'] = {}       
            try:
                for func in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if func is not None:
                        fname = func.name.decode('ascii')
                        modules[module_name]['export'][fname] = hash_function(fname)
            except Exception:
                pass
    
    with open('hashes.txt', 'w') as f:
        f.write(json.dumps(modules, indent=4))


if __name__ == "__main__":
    main()
        