#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
import os
import sys
import struct
import time
import random
import traceback # useful for exception handling
import threading
# NOTE: Do not import any other modules - the ones above should be sufficient
import select

def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.203.')
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=2, count=10)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=2, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)
        
        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        args = parser.parse_args()
        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: bytes) -> int:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, seq: int, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.3f ms" % (packetLength, destinationHostname, destinationAddress, seq, ttl, time))
        else:
            print("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms" % (packetLength, destinationAddress, seq, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))

    def printOneTraceRouteIteration(self, ttl: int, destinationAddress: str, measurements: list, destinationHostname=''):
        latencies = ''
        noResponse = True
        for rtt in measurements:
            if rtt is not None:
                latencies += str(round(rtt, 3))
                latencies += ' ms  '
                noResponse = False
            else:
                latencies += '* ' 

        if noResponse is False:
            print("%d %s (%s) %s" % (ttl, destinationHostname, destinationAddress, latencies))
        else:
            print("%d %s" % (ttl, latencies))

class ICMPPing(NetworkApplication):

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout):
        # 1. Wait for the socket to receive a reply
        recv = select.select([icmpSocket], [], [], timeout)#wait until ready for reading\writing\exceptional condition,recv是一个返回的三元组
        # 2. If reply received, record time of receipt, otherwise, handle timeout
        if recv[0]==[]:
                return
        timeOfReceipt=time.time()
        # 3. Unpack the imcp and ip headers for useful information, including Identifier, TTL, sequence number 
        rec_packet,rec_address = icmpSocket.recvfrom(1024)
        rec_icmp_header = rec_packet[20:28]
        rec_ip_header = rec_packet[:20]
        rec_ip_TTL = struct.unpack('!B', rec_ip_header[8:9])[0]
        rec_ip_totalLength = struct.unpack('!H', rec_ip_header[2:4])[0]
        rec_icmp_identifier, rec_icmp_sequence = struct.unpack("!HH", rec_icmp_header[4:8])
        # 5. Check that the Identifier (ID) matches between the request and reply
        if ID == rec_icmp_identifier:
        # 6. Return time of receipt, TTL, packetSize, sequence number
                return timeOfReceipt,rec_ip_TTL,rec_ip_totalLength,rec_icmp_sequence

    def sendOnePing(self, icmpSocket, destinationAddress, ID, seq_num):
        # 1. Build ICMP header
        timeOfSending=time.time()
        payload = struct.pack('!d',timeOfSending)#! is network (= big-endian),d is double(8)
        header = struct.pack(
                '!BBHHH',#Format Characters,B is unsigned char(8), H is unsigned short(16)
                8,#type,ping program sends an ICMP type 8 code 0, send back a type 0 code 0 ICMP echo reply
                0,#code field
                0,#checksum,pseudo header's checksum is 0
                ID,#Identifier
                seq_num#Sequence Number
                )
        # 2. Checksum ICMP packet using given function
        checksum=self.checksum(header)
        # 3. Insert checksum into packet
        header = struct.pack(
                '!BBHHH',
                8,
                0,
                checksum,#insert the real checksum into packet
                ID,
                seq_num
                )
        icmp = header + payload
        # 4. Send packet using socket
        ''' 0 is port number'''
        icmpSocket.sendto(icmp,(destinationAddress,0))
        # 5. Return time of sending
        return timeOfSending

    def doOnePing(self, destinationAddress, packetID, seq_num, timeout):
        # 1. Create ICMP socket
        '''
        class socket.socket(family=AF_INET, type=SOCK_STREAM, proto=0)
        The address family should be AF_INET (the default), AF_INET6, AF_UNIX, AF_CAN, AF_PACKET, or AF_RDS
        The socket type should be SOCK_STREAM (the default), SOCK_DGRAM, SOCK_RAW or perhaps one of the other SOCK_ constants
        The protocol number is usually zero and may be omitted or in the case where the address family is AF_CAN the protocol should be one of CAN_RAW, CAN_BCM, CAN_ISOTP or CAN_J1939    

        socket.AF_INET is for IPv4,socket.SOCK_RAW is for raw packet
        getprotobyname will translate an internet protocol name to a constant suitable for passing as the third argument to the socket() function. needed for sockets opened in “raw” mode

        '''
        icmpSocket = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.getprotobyname("icmp"))
        icmpSocket.settimeout(timeout)
        # 2. Call sendOnePing function
        timeOfSending = self.sendOnePing(icmpSocket,destinationAddress, packetID,seq_num)
        # 3. Call receiveOnePing function
        timeOfReceipt,TTL,packetSize,sequenceNumber=self.receiveOnePing(icmpSocket,destinationAddress,packetID,timeout)
        # 4. Close ICMP socket
        icmpSocket.close()
        # 5. Print out the delay (and other relevant details) using the printOneResult method, below is just an example.
        self.printOneResult(destinationAddress, packetSize, (timeOfReceipt-timeOfSending)*1000, sequenceNumber, TTL,args.hostname) 


    def __init__(self, args):
        print('Ping to: %s...' % (args.hostname))
        # 1. Look up hostname, resolving it to an IP address
        destinationAddress = socket.gethostbyname(args.hostname)
        # 2. Repeat below args.count times
        for i in range(args.count):
        # 3. Call doOnePing function, approximately every second, below is just an example
                self.doOnePing(destinationAddress, os.getpid(), i+1, args.timeout)
                time.sleep(1)

class Traceroute(NetworkApplication):
    def __init__(self, args):
        #1. get destination address
        print('Traceroute to: %s...' % (args.hostname))
        self.destinationAddress = socket.gethostbyname(args.hostname)
        #2. instantiate my socket
        if args.protocol=="icmp":
            self.protocol=socket.IPPROTO_ICMP
            self.mySocket=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
        elif args.protocol=="udp":
            self.protocol=socket.IPPROTO_UDP
            self.mySocket=socket.socket(socket.AF_INET, socket.SOCK_DGRAM,socket.IPPROTO_UDP)
        else:
            print("protocol must be icmp or udp")
            return
        self.mySocket.settimeout(args.timeout)
        self.packetID=os.getpid()
        self.DoTraceRoute()

    def DoTraceRoute(self):
        #3. init parameter
        stop = False
        self.seqNum=0
        self.TTL=0
        self.sendTime=[]#length is seqNum
        self.recTime=[]
        #4. start TraceRoute Iteration
        while not stop and self.TTL<64:
            #5. change TTL using setsockopt
            self.TTL+=1
            self.mySocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, self.TTL)
            stop = self.doOneTraceRouteIteration()
            
    def doOneTraceRouteIteration(self):
        recPackets=["","",""]
        recAddress=["","",""]
        measurements=[]
        for i in range(3):
            self.seqNum+=1
            #6. send ICMP/UDP packet
            self.sendTime.append(time.time())
            if self.protocol == socket.IPPROTO_ICMP:
                self.sendICMP()
            elif self.protocol == socket.IPPROTO_UDP:
                self.sendUDP()
            else:
                print("error")
                return
        #9. receive packet
            recPackets[i],recAddress[i] = self.mySocket.recvfrom(2048)
            self.recTime.append(time.time())
            measurements.append((self.recTime[self.seqNum-1]-self.sendTime[self.seqNum-1])*1000)


        #11. unpack the packet. return true if the packet is send to the destination successfully
        recIcmpHeader = recPackets[0][20:28]
        icmpType, icmpCode = struct.unpack("!BB", recIcmpHeader[0:2])
        stop = True
        if icmpType==11 and icmpCode==0:
            stop = False
            
        #10. check if the addresses are same. print result if it is
        if recAddress[0]==recAddress[1]==recAddress[2]:
            try:
                hostName = socket.gethostbyaddr(recAddress[0][0])[0]
            except socket.herror as e:
                hostName = recAddress[0][0]
            self.printOneTraceRouteIteration(self.TTL,recAddress[0][0],measurements,hostName)
        else:
            print("the packet went to different routers")

        return stop

    def sendICMP(self):
        #7. build ICMP packet and send
        header = struct.pack('!BBHHH',8,0,0,self.packetID,self.seqNum)
        checksum=self.checksum(header)
        header = struct.pack('!BBHHH',8,0,checksum,self.packetID,self.seqNum)
        self.mySocket.sendto(header,(self.destinationAddress,0))
    def sendUDP(self):
        #8. send UDP packet
        self.mySocket.sendto(struct.pack('!d', timestamp), (self.destinationAddress, 33434))


            
class WebServer(NetworkApplication):

    def handleRequest(tcpSocket):
        # 1. Receive request message from the client on connection socket
        # 2. Extract the path of the requested object from the message (second part of the HTTP header)
        # 3. Read the corresponding file from disk
        # 4. Store in temporary buffer
        # 5. Send the correct HTTP response error
        # 6. Send the content of the file to the socket
        # 7. Close the connection socket
        pass

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
        # 1. Create server socket
        # 2. Bind the server socket to server address and server port
        # 3. Continuously listen for connections to server socket
        # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
        # 5. Close server socket


class Proxy(NetworkApplication):

    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))

# Do not delete or modify the code below
if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
