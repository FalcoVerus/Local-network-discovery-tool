# Local-network-discovery-tool
The script is listing the currently available network interfaces and asking for user input for the IP addresses to determine the scane range. 

The user can select, what type of scan they want to run, currently 4 different type are available:
  ICMP ping,
  ARP lookup,
  Scanning specific TCP ports and 
  Scanning all TCP and UDP ports

Once selected the above scans will be concluded on the specified data range, the results will be printed and stored in a dataframe. 
At the end of the execution the dataframe is written in a .csv file. 

Please note, that TCP/UDP portscanning can take a long time to be finished. 
