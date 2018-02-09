import binascii
import os

exe_name = 'remcomsvc'

header = '%s_DATA = ' % exe_name.upper()
indent = " " * len(header)

# we are 1 off from 80 - 2 (' and ') - 2 ( \) - length of the header
payload_line_length = 79 - 2 -2 - len(header)

in_data = open("/Users/jborean/Downloads/%s.exe" % exe_name, "rb")
content = in_data.read()
payload = binascii.hexlify(content).decode('utf-8')

payload_length = len(payload)
print(payload_length)
index = 0
end_index = 0
buffer = ""

if os.path.isfile("%s.py" % exe_name):
    os.remove("%s.py" % exe_name)

out_data = open("%s.py" % exe_name, "w+")
out_data.write("%s'" % header)

while True:
    if end_index + payload_line_length > payload_length:
        end_index = payload_length
    else:
        end_index += payload_line_length

    buffer = payload[index:end_index]
    if end_index < payload_length:
        out_data.write("%s' \\\n%s'" % (buffer, indent))
    else:
        out_data.write("%s'\n" % buffer)
        break
    index += payload_line_length
