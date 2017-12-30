# DMPLS
Distributes Mass Password Logging System

Modifications to OpenSSH in order to log cleartext credentials to syslog.
Credentials are logged in base64 in order to avoid problems with non alpha/numeric characters.
Often times brute force bots will use comma, space and/or non-ASCII characters and this makes it difficult to parse fields from a text based log file.
The Base64 encoding makes it possible to create an easily parsable comma separated log entry.

Sample Log Line (credentials: user=testuser  password=test,password)

DMPL:: Remote IP: 192.168.1.10, Port: 61797, User: dGVzdHVzZXI=, Password: dGVzdCxwYXNzd29yZA==
