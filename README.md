# Log4jTools
Tools for investigating Log4j CVE-2021-44228

## FetchPayload.py (Get java payload from ldap path provided in JNDI lookup).
Example command:

Requirements: curl (system), requests (python)
```
python FetchPayload.py ldap://maliciouserver:1337/path

[+] getting object from ldap://maliciouserver:1337/path
[+] exploit payload: http://maliciouserver:80/Exploit.class
[+] seeing if attacker left behind un-compile payload http://maliciouserver:80/Exploit.java
[x] failed to find payload Exploit.java
[+] trying to fetch compiled payload http://maliciouserver:80/Exploit.class
[+] found payload and saved to file Exploit.class_
