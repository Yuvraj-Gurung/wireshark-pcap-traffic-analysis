# Wireshark PCAP Traffic Analysis

## 1. Introduction

Malware traffic analysis is a crucial skill for cybersecurity professionals. It involves capturing and analyzing network traffic to detect malicious activities. This project focuses on using Wireshark, a popular network protocol analyzer, to identify and analyze malware traffic. 

## 2. Objectives

- Investigate suspicious network activity in an Active Directory (AD) environment.
- Analyze the captured traffic and identify potential malware.
- Recognize patterns and behaviors associated with malware.

## 3. Prerequisites

- Basic knowledge of networking concepts.
- Understanding of common network protocols (HTTP, DNS, TCP/IP).
- Familiarity with Wireshark.

## 4. Tools and Software

- **Wireshark**: Network protocol analyzer.
- **PCAP Files**: Pre-captured network traffic files for analysis.

## 5. Setting Up the Environment

1. **Install Wireshark**: Download and install Wireshark from [Wireshark's official website](https://www.wireshark.org/download.html).
2. **Prepare PCAP Files**: Obtain PCAP files containing malware traffic for analysis. Websites like [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/) provide sample PCAP files.

## 6. Importing the Pcap

1. **Launch Wireshark**: Wireshark -> File -> Open -> Select the Pcap File

<img src="images/image 1.png"> <img src="images/image 2.png"> <img src="images/image 3.png"> 
<img src="images/image 4.png"> <img src="images/image 5.png"> <img src="images/image 6.png">

## 6. Analyzing Malware Traffic

**Step 1: 💻 Victim Details**

1. Filter on web traffic to find the victim's IP and MAC address.

For example: 
(http.request or tls.handshake.type eq 1) and !(ssdp)

<img src="images/image 7.png">

2. Finding a Windows host name in NBNS or SMB traffic.

For example:
nbns or smb or smb2

<img src="images/image 8.png">

3. Finding the victim's Windows user account name in Kerberos traffic.

For example:
Kerberos.CNameString

<img src="images/image 9.png">


**Step 2: 💻 Identifying the Malware**

1. Determining the highly suspicious HTTP traffic over TCP port 80.

For example:
(http.request) and !(ssdp)

<img src="images/image 10.png"> <img src="images/image 11.png">

2. Exporting the file using Wireshark's Export Objects function.

File -> Export Objects -> HTTP -> Select the file to export -> Save

<img src="images/image 12.png"> <img src="images/image 13.png">

3. Determine the file type and SHA256 hash of the exported object.

For example:

file file_name

shasum -a 256 file_name

<img src="images/image 14.png">


**Step 3: 💻 Post-infection Traffic**

1. Filtering for HTTPS web traffic directly to IP address.

For example:

tls.handshake.type eq 1 and !(tls.handshake.extension.type eq 0)

<img src="images/image 15.png">

2. Reviewing endpoint statistics for IPv4 addresses on the filtered results.

Statistics -> Endpoints -> IPv4

<img src="images/image 16.png"> <img src="images/image 17.png">

3. Reviewing the HTTPS certificate issuer data for Qakbot C2 server.

For example:

tls.handshake.type eq 11 and ip.addr eq IP_Address 1

tls.handshake.type eq 11 and ip.addr eq IP_Address 2

tls.handshake.type eq 11 and ip.addr eq IP_Address 3

<img src="images/image 18.png"> <img src="images/image 19.png"> <img src="images/image 20.png">


4. Finding and reviewing Qakbot traffic over TCP port (65400).

For example:
tcp.port eq 65400 and tcp.flags eq 0x0002

<img src="images/image 21.png"> <img src="images/image 22.png">


**Step 4: 💻 Follow-up Spambot Activity**

1. Filtering for SMTP traffic to determine possible spambot activity.

For example:

smtp

<img src="images/image 23.png">

smtp.req.command contains "EHLO"

<img src="images/image 24.png">

2. Filtering for TLS encrypted email traffic.

For example:

tls.handshake.type eq 1 and (tcp.port eq 25 or tcp.port eq 465 or tcp.port eq 587)

3. Check if any emails were sent over unencrypted SMTP traffic.

File -> Export Objects -> IMF

<img src="images/image 25.png"> <img src="images/image 26.png">

**Note**: Here we see that there is no spambot emails available to export.


**Step 5: 💻 Follow-up VNC Activity**

1. Finding VNC traffic from the Qakbot infection.

For example:
ip.addr eq IP_Address and tcp.flags eq 0x0002

<img src="images/image 27.png"> <img src="images/image 28.png"> <img src="images/image 29.png"> <img src="images/image 30.png">


**Step 6: 💻 ARP Scanning**

1. Finding the ARP scanning traffic from the Qakbot-infected host.

For example:

arp and eth.dst eq ff:ff:ff:ff:ff:ff

<img src="images/image 31.png">

icmp

<img src="images/image 32.png">

ip.addr eq Ip_address

<img src="images/image 33.png">


**Step 7: 💻 File Transfer Over SMB**

1. Finding file transfers over SMB.

For example:

File -> Export Objects -> SMB

<img src="images/image 34.png"> <img src="images/image 35.png">

**Note**: Here we see that there are some suspicious files in SMB object list.

2. Selecting each of these files and exporting them from the pcap.

For example:

File -> Export Objects -> SMB -> Select the suspicious files -> Save

3. Determining the file types and SHA256 hashes of the files exported from SMB traffic.

For example:

<img src="images/image 36.png">

4. Filter on smb2 to review the SMB traffic used for these file transfers.

<img src="images/image 37.png"> <img src="images/image 38.png">


## 7. Conclusion

By completing this project, I have gained hands-on experience in analyzing network traffic using Wireshark. Understanding malware traffic patterns and behaviors is essential for detecting and mitigating cyber threats.
