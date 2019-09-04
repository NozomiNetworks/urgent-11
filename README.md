# Urgent/11 
Toolkit collection developed to help network defenders detecting Urgent/11 vulnerabilities

# Nmap NSE script
script used for check potential vulnerable devices exposing VxWorks RTOS

## Requirements
This script requires Nmap to run. If you do not have Nmap download and Install the tool based off the Nmap instructions. https://nmap.org/book/install.html

### Windows

After downloading vxworks_urgent11.nse you'll need to move it into the default NSE Scripts directory (administrative privilage needed). Go to Start -> Programs -> Accessories, right click on 'Command Prompt'. Select 'Run as Administrator'.

`move vxworks_urgent11.nse C:\Program Files (x86)\Nmap\scripts`

### Linux

After downloading vxworks_urgent11.nse you'll need to move it into the default NSE Scripts directory (root privilage needed).

`sudo mv vxworks_urgent11.nse /usr/share/nmap/scripts`

## Usage
Inside a Terminal Window/Command Prompt use the following command where host is the target you wish you scan for Urgent/11.

`Windows/Linux: nmap -p 21 --script vxworks_urgent11 <host>`

Note: to speed up results by avoiding DNS lookups during the scan use the -n option, also disable pings to determine if the device is up by doing a -Pn option for full results.

`nmap -p 21 -Pn -n --script vxworks_urgent11 <host>`

## Notes
The vxworks_urgent11.nse script is able to detect any exposes banner within the FTP protocol and based on the version of VxWorks, will print out the related CVE(s)

The list of vulnerable versions can be found in the Security Announcement made by Wind River: `https://www.windriver.com/security/announcements/tcp-ip-network-stack-ipnet-urgent11/security-advisory-ipnet/`