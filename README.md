# synprobe
synprobe.py is a simple network reconnaissance tool developed using Scapy framework.
In the script, I probe a given port with a SYN packet to see if the port is open or
not. 

If the port is open then we establish a TCP connection to that port by doing a 3 way
TCP handshake to do service fingerprinting. After establishing TCP handshake, I print
the first 1024 bytes sent by the server and if the server dont send any data then I
send some random payload("GET /index.html HTTP/1.1\r\n\r\n") and print the response.

After scanning the port, I issue a FIN packet to initiate the connection termination
process.

## Note: 
Since scapy does not use Linux Kernel services, Linux Kernel might issue RST 
for SYN packets created by Scapy. To supress RST packets from Kernel excecute the 
following comand with your IP:
```
iptables -A OUTPUT -p tcp --tcp-flags RST RST -s {SRC_IP} -j DROP
```

## Instructions to run
```
# For help menu
root@kali:~# python synprobe.py -h

# Examples

## Scan port 80 of 192.168.1.100
root@kali:~# python synprobe.py 192.168.1.100 -p 22

## Scan common TCP ports of 192.168.1.100
root@kali:~# python synprobe.py 192.168.1.100

## Scan a range of ports
root@kali:~# python synprobe.py 192.168.1.100 -p 1-100

## Scan a subnet
root@kali:~# python synprobe.py 192.168.1.0/24 -p 1-100

```
