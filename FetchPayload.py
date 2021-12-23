#!/usr/bin/python
import os
import sys
import requests
import hashlib

def save_file(file_name, file_data):
    with open(file_name, 'wb') as f:
        f.write(file_data)
        f.close()


def parse_object_line(line, prefix):
    str_ptr = line.find(prefix)
    if str_ptr == -1:
        return None

    param_ptr = line[str_ptr:].find(' ')
    if param_ptr == -1:
        return None

    str_ptr += param_ptr

    param = str(line[str_ptr+1:]).replace(' ', '')
    if len(param) == 0:
        return None

    return param


def get_remote_payload(base_url, payload_name):
    try:
        response = requests.get(base_url + payload_name)
        if response.status_code == 200 and len(response.content):
            hash_value = hashlib.sha256((base_url + payload_name)).hexdigest()
            file_name = payload_name + '_' + hash_value
            print ("Hashing string %s" % base_url + payload_name)
            save_file(file_name, response.content)
            print("[+] Found payload and saved to file %s" % file_name)
            return True

    except Exception as e:
        print("[x] Request to url %s failed, exception: %s" % (base_url+payload_name, e))

    print("[x] Failed to find payload %s" % payload_name)
    return False


if __name__ == '__main__':
    if len(sys.argv) <= 1:
        raise RuntimeError('Usage: ./FetchPayload.py ldap://server/path')

print("[+] Getting object from %s" % sys.argv[1])


# probably need some error handling, will look into this later
stream = os.popen("curl -s " + sys.argv[1])
data = stream.read()
parts = data.split('\n')

code_base = ''
class_name = ''

for part in parts:
    temp = parse_object_line(part, "javaCodeBase:")
    if temp:
        code_base = temp

    temp = parse_object_line(part, "javaFactory:")
    if temp:
        class_name = temp

if not code_base:
    raise RuntimeError("Failed to find code base.")

if not class_name:
    raise RuntimeError("Failed to find class name.")

class_payload = class_name + '.class'
java_payload = class_name + '.java'
payload_found = False

print("[+] Exploit payload: %s" % code_base + class_payload)

print("[+] Checking if attacker left behind source payload %s" % code_base + java_payload)
if get_remote_payload(code_base, java_payload):
    payload_found = True

print("[+] Trying to fetch compiled payload %s" % code_base + class_payload)
if get_remote_payload(code_base, class_payload):
    payload_found = True

if not payload_found:
    print("[x] Couldn't find any payloads on the server")
