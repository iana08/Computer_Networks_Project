CONTENTS OF THIS FILE
---------------------

 * Introduction
 * Installation
 * Configuration

Introduction

This is a client-server duo code and a stand alone application to detect network compression on a network between two computers. 

For the server-client code: 
	
	It first sets up a TCP connection with the server and the server responds that it will be listening on the udp port provided by the client computer through a myconfig.json file. 
	Then the server will accept all the UPD packets by the client request and keep track of the time of how long it took for the packets to get from the client to the server.
	Then the client, after sending x amount of packets (provided by the myconfig.json file), will stop listening by reading the packet-id on the packet set in the payload. And open a TCP port so the client can connect to and will respond with whether there is compression on the network or not. 

For the Stand alone code:

	It first sends a raw SYN TCP packet to the server that has it's ports close. So it will get a RST packet back.
	But sadly I wasn't able to do that. 	
	But it was able to send the UDP packets and set the payload id with the random data is set too by urandom.
	And then send another TCP connection to the server, from the myconfig.json file too
	But it is able to set up the TCP packet and UDP packets
	and sends them but not able to recieve the RST, sadly instead of terminates it just continues to sends the UDP packets and then the TCP packets.
	
Installation:

	to make : type 

		make


	The make file should take care of it


Configuration

	To Run on Client computer.

		sudo ./compdetect_client myconfig.json <host_ip> 

	It needs the host ip because I was not able to figure out how to get the host_ip of the client computer.

	To Run on Server computer:

		sudo ./compdetect_server myconfig.json

	Yay nothing added here because there is no reason to keep track of the source server because Im not sending anything back to the server other than the Final TCP connection.

	To run stand alone code: 

		sudo ./compdetect myconfig.json <host_ip>

	And that is it.
