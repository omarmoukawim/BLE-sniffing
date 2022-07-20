#from subprocess import Popen, PIPE





from __future__ import print_function

import argparse
import binascii
from builtins import input
from datetime import datetime
import errno
import logging.handlers
import select

import six
from six import StringIO
import struct
import sys
import threading
import time
import datetime
import types

from pprint import pprint
import os

import usb.core

#  ***************************************
#             ENABLE DEBUG
#  ***************************************

# >set PYUSB_DEBUG=debug
# >set LIBUSB_DEBUG=4

#libusb-wi32 filter installer

#import usb.backend.libusb0
#import usb.backend.libusb1
#
#
#
#backend1 = usb.backend.libusb1.get_backend(find_library=lambda x: "D:\\Program Files (x86)\\Python38\\Lib\\site-packages\\libusb\\_platform\\_windows\\x86\\libusb-1.0.dll")
#backend0 = usb.backend.libusb0.get_backend()
#
#use_backend = backend1

stats = {}

#global var
last_rolling_code = ()



try:
    from inspect import getfullargspec

    def is_callback_valid(cb):
        args = getfullargspec(cb).args
        return len(args) > 1
except:
    from inspect import getargspec

    def is_callback_valid(cb):
        args = getargspec(cb)[0]
        return len(args) > 1


class CC2540EMK:
    """CC2540EMK is used to manage the USB device.
    """
    DEFAULT_CHANNEL = 0x27

    DATA_EP = 0x83
    DATA_TIMEOUT = 2500

    DIR_OUT = 0x40
    DIR_IN = 0xc0

    GET_IDENT = 0xc0
    SET_POWER = 0xc5
    GET_POWER = 0xc6

    SET_START = 0xd0  # bulk in starts
    SET_STOP = 0xd1  # bulk in stops
    SET_CHAN = 0xd2  # 0x0d (idx 0) + data)0x00 (idx 1)

    COMMAND_FRAME = 0x00

    COMMAND_CHANNEL = 0x01 #????

    def __init__(self, callback, channel=DEFAULT_CHANNEL):
        """Create a new CC2540EMK manager object
        
        This constructor consumes the first sniffer available on the USB bus.
            
        Args:
            callback(func): A function that will handle any received packets, 
                            with a signature (timestamp, frame).
            channel(int): The channel to sniff on.
        """

        self.dev = None
        self.channel = channel
        self.callback = callback
        self.thread = None
        self.running = False
        self.thread_wd = None
        self.has_to_run = False
        self.ts_first_start = None

        stats['Captured'] = 0
        stats['Non-Frame'] = 0

        if self.callback is None:
            raise ValueError("A valid callback must be provided")
        if not is_callback_valid(self.callback):
            raise ValueError("Callback must have at least 2 arguments")
        
        self.init_hw(verbose=True)

    
    def init_hw(self, verbose=False):
        print("init_hw")
        try:
            if(verbose==True): print("find")
            time.sleep(0.1)
            #self.dev = usb.core.find(backend=use_backend, idVendor=0x0451, idProduct=0x16b3)
            self.dev = usb.core.find(idVendor=0x0451, idProduct=0x16b3)
        except usb.core.USBError:
            raise OSError(
                "Permission denied, you need to add an udev rule for this device",
                errno=errno.EACCES)

        if self.dev is None:
            raise IOError("Device not found")

        if(verbose==True): print("set_configuration")
        time.sleep(0.1)
        self.dev.set_configuration()  # must call this to establish the USB's "Config"
        
        if(verbose==True): print("self.name = self.dev.product")
        time.sleep(0.1)
        self.name = self.dev.product or "Default name"
        if(verbose==True): print("self.name = %s" % self.name)
        
        if(verbose==True): print("GET_IDENT = 0xc0")
        time.sleep(0.1)
        #self.ident = self.dev.ctrl_transfer(0xc0, 0xc0, 0, 0, 256)  # get identity from Firmware command
        self.ident = self.dev.ctrl_transfer(CC2540EMK.DIR_IN, CC2540EMK.GET_IDENT, 0, 0, 256)  # get identity from Firmware command
        if(verbose==True): print("self.ident>> %s" % binascii.hexlify(self.ident))

        if(verbose==True): print("SET_POWER")
        time.sleep(0.1)
        # power on radio, wIndex = 4
        self.dev.ctrl_transfer(CC2540EMK.DIR_OUT, CC2540EMK.SET_POWER, wIndex=4)

        while True:
            # check if powered up
            if(verbose==True): print("GET_POWER")
            time.sleep(0.1)
            power_status = self.dev.ctrl_transfer(CC2540EMK.DIR_IN,
                                                  CC2540EMK.GET_POWER, 0, 0, 1)
            if power_status[0] == 4: break
            time.sleep(0.1)

        if(verbose==True): print("set_channel")
        time.sleep(0.1)
        self.set_channel(channel)
        
        if(verbose==True): print("\n\n\npprint(dev._get_full_descriptor_str())")
        if(verbose==True): print(self.dev._get_full_descriptor_str() + "\n")
        
        if(verbose==True): print("print(config)")
        if(verbose==True): 
            for config in self.dev:
                print(config)  
        print("init_hw done")

    
    def __del__(self):
        if self.dev:
            # power off radio, wIndex = 0
            self.dev.ctrl_transfer(self.DIR_OUT, self.SET_POWER, wIndex=0)

    def start(self):
        # start sniffing
        self.running = True
        self.dev.ctrl_transfer(CC2540EMK.DIR_OUT, CC2540EMK.SET_START)
        self.thread = threading.Thread(target=self.recv)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        # end sniffing
        self.running = False
        self.thread.join()
        self.dev.ctrl_transfer(CC2540EMK.DIR_OUT, CC2540EMK.SET_STOP)

    def one_start(self):
        # start sniffing
        print("one_start")
        self.dev.ctrl_transfer(CC2540EMK.DIR_OUT, CC2540EMK.SET_START)
        

    def one_stop(self):
        # end sniffing
        print("one_stop")
        self.dev.ctrl_transfer(CC2540EMK.DIR_OUT, CC2540EMK.SET_STOP)

    def one_read(self):
        bytesteam = self.dev.read(CC2540EMK.DATA_EP, 64, timeout=100)
        print("RECV>> %s" % binascii.hexlify(bytesteam))

    def isRunning(self):
        return self.running

    def isSniffing(self):
        return self.has_to_run

    def start_sniff(self):
        self.start()
        self.has_to_run = True
        self.thread_wd = threading.Thread(target=self.watchdog)
        self.thread_wd.daemon = True
        self.thread_wd.start()

    def stop_sniff(self):
        # end sniffing
        self.has_to_run = False
        self.thread_wd.join()
        self.stop()
        print("stop_sniff DONE")
        
    def watchdog(self):
        while self.has_to_run:
            if self.running:
                #nothing
                time.sleep(0.2)
            else:
                #stop sniffing
                self.stop()
                time.sleep(0.2)
                self.init_hw()
                time.sleep(0.2)
                self.start()
        # has_to_run = false
                
    def recv(self):

        # While the running flag is set, continue to read from the USB device
        self.ts_first_start =  '{0:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now())
        print("Started @ %s" % self.ts_first_start)
        while self.running:
            try:
                bytesteam = self.dev.read(
                    CC2540EMK.DATA_EP, 64, timeout=CC2540EMK.DATA_TIMEOUT)
                #print("RECV>> %s" % binascii.hexlify(bytesteam))
            except usb.core.USBError as e:
#                print("been started @ %s" % self.ts_first_start)
#                print("usb.core.USBError @ %s" % '{0:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()))
#                raise e
                
                if e.errno == 10060:
                    print("usb.core.USBTimeoutError @ %s" % '{0:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()))
                    self.running = False
                    continue
                if e.errno == 110:
                    print("usb.core.USBTimeoutError @ %s" % '{0:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()))
                    self.running = True
                    continue
                else:
                    raise e
                
                
              
            if len(bytesteam) >= 3:
                (cmd, cmdLen) = struct.unpack_from("<BH", bytesteam)
                bytesteam = bytesteam[3:]
                if len(bytesteam) == cmdLen:
                    # buffer contains the correct number of bytes
                    if CC2540EMK.COMMAND_FRAME == cmd:
                        #logger.info('Read a frame of size %d' % (cmdLen, ))
                        #print('Read a frame of size %d' % (cmdLen, ))
                        stats['Captured'] += 1
                        (timestamp, pktLen) = struct.unpack_from("<IB",
                                                                 bytesteam)
                        frame = bytesteam[5:]
          
                        if len(frame) == pktLen:
                            self.callback(timestamp, frame)
                        else:
#                            logger.warn(
#                                "Received a frame with incorrect length, pkgLen:%d, len(frame):%d"
#                                % (pktLen, len(frame)))
                            print(
                                "Received a frame with incorrect length, pkgLen:%d, len(frame):%d"
                                % (pktLen, len(frame)))
                            stats['Non-Frame'] += 1
          
                    # elif cmd == CC2540EMK.COMMAND_CHANNEL:
#                        #logger.info('Received a command response: [%02x %02x]' % (cmd, bytesteam[0]))
#                        print("@ %s" % '{0:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()))
#                        print("RECV>> %s" % binascii.hexlify(bytesteam))
#                        print('Received a command response: [%02x %02x]' % (cmd, bytesteam[0]))
#                        # We'll only ever see this if the user asked for it, so we are
#                        # running interactive. Print away
#                        print('Sniffing in channel: %d' % (bytesteam[0],))
                        # print("!", end = '', flush=True)
                        # print('Received on COMMAND_CHANNEL [cmd cmdLen]: [%02x %02x]' % (cmd, cmdLen))
                        # print("RECV>> %s" % binascii.hexlify(bytesteam))
                        # self.one_stop()
                        # self.one_start()
                    # else:
#                        #logger.warn("Received a command response with unknown code - CMD:%02x byte:%02x]" % (cmd, bytesteam[0]))
#                        print("@ %s" % '{0:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()))
#                        print("Received a command response with unknown code - CMD:%02x byte:%02x]" % (cmd, bytesteam[0]))
#                        print("RECV>> %s" % binascii.hexlify(bytesteam))
                        # print("?", end = '', flush=True)
        #print("Stopped @ %s" % '{0:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()))    
            
    def set_channel(self, channel):
        was_running = self.running

        if 37 <= channel <= 39:
            if self.running:
                self.stop()

            self.channel = channel

            # set channel command
            self.dev.ctrl_transfer(CC2540EMK.DIR_OUT, CC2540EMK.SET_CHAN, 0, 0,
                                   [channel])
            self.dev.ctrl_transfer(CC2540EMK.DIR_OUT, CC2540EMK.SET_CHAN, 0, 1,
                                   [0x00])

            self.get_channel()

            if was_running:
                self.start()

        else:
            raise ValueError("Channel must be between 11 and 26")

    def get_channel(self):
        return self.channel

    def __repr__(self):
        if self.dev:
            return "%s <Channel: %d>" % (self.name, self.channel)
        else:
            return "Not connected"



def dump_stats():
    s = StringIO()

    s.write('Frame Stats:\n')
    for k, v in stats.items():
        s.write('%20s: %d\n' % (k, v))

    print(s.getvalue())


      
if __name__ == '__main__':
#    args = arg_parser()
#    log_init()
#
#    logger.info('Started logging')
#    start_datetime = datetime.now()
#
#    packetHandler = PacketHandler()
#    packetHandler.enable()
#
#    if args.annotation is not None:
#        packetHandler.setAnnotation(args.annotation)
#
#    # Create a list of handlers to dispatch to, NB: handlers must have a "handleSniffedPacket" method
#    handlers = [packetHandler]
#
#    def handlerDispatcher(timestamp, macPDU):
#        """ Dispatches any received packets to all registered handlers
#
#        Args:
#            timestamp: The timestamp the packet was received, as reported by 
#                       the sniffer device, in microseconds.
#            macPDU: The 802.15.4 MAC-layer PDU, starting with the Frame Control 
#                    Field (FCF).
#        """
#        if len(macPDU) > 0:
#            packet = SniffedPacket(macPDU, timestamp)
#            for handler in handlers:
#                handler.handleSniffedPacket(packet)
#
#    snifferDev = CC2531EMK(handlerDispatcher, args.channel)
    
    #testing DEVICE handle
    dev = None
    channel=CC2540EMK.DEFAULT_CHANNEL
    
    

    def handlerDispatcher(timestamp, macPDU):
        """ Dispatches any received packets to all registered handlers

        Args:
            timestamp: The timestamp the packet was received, as reported by 
                       the sniffer device, in microseconds.
            macPDU: The 802.15.4 MAC-layer PDU, starting with the Frame Control 
                    Field (FCF).
        """
        global last_rolling_code
        
        if len(macPDU) > 0:
            #print("%10d: %s" % (timestamp, binascii.hexlify(macPDU)))
            payload = macPDU[0:-2]
            rssi_fcs = macPDU[-2:]
              
            rssi = rssi_fcs[0]-94
            exflags = rssi_fcs[1]
            bchannel=exflags&0x7f
            fcsok=(exflags&0x80 > 0)
            
            ble_aa = payload[0:4]
            ble_pdu = payload[4:-3]
            ble_crc = payload[-3:]

            ble_pdu_head = ble_pdu[0:2]  # first 2 payload bytes are for BLE HEADER
            ble_pdu_payload = ble_pdu[2:]
            adv_addr = ble_pdu_payload[0:6]
            adv_addr_big_endian = bytearray(adv_addr)
            adv_addr_big_endian.reverse()

            adv_data = ble_pdu_payload[6:]

            adv_addr_int = int.from_bytes(adv_addr, byteorder='little')
            add1 = int('0x03160628afa4',16)
            add2 = int('0x03160628afa5',16)
            add3 = int('0x03160628afa6',16)
            add4 = int('0x03160628afa7',16)
            # print("ADV_DATA_INT: ", adv_addr_hex)
            #      ts   aa pdu crc  rssi ch fcsok
            if(fcsok and (adv_addr_int == add1 or adv_addr_int == add2 or adv_addr_int == add3 or adv_addr_int == add4)): #STAMPA NEL FILE
                # print("%10d: %s %s %s    %d  %d  %s" % (timestamp, binascii.hexlify(ble_aa), binascii.hexlify(ble_pdu), binascii.hexlify(ble_crc), rssi, bchannel, fcsok))
                print("\nPACKET FROM SILVAIR:","\ntimestamp: ",timestamp,"\nble_acc_addr: ",binascii.hexlify(ble_aa),"\nble_header: ",binascii.hexlify(ble_pdu_head), "\nadv_addr: ",binascii.hexlify(adv_addr_big_endian),"\nadv_data: ",binascii.hexlify(adv_data),"\nble_crc: ", binascii.hexlify(ble_crc), "\nRSSI", rssi, "\nChannel", bchannel, "\nFCSOK", fcsok)
                # print("adv_addr={}".format(adv_addr))
                # print("carciofo ***********adv_addr int: ",adv_addr_hex)
            else:
                if(fcsok):
                    print("\nPACKET NOT FROM SILVAIR", "\ntimestamp: ", timestamp, "\nble_acc_addr: ", binascii.hexlify(ble_aa), "\nble_header: ", binascii.hexlify(ble_pdu_head), "\nadv_addr: ",binascii.hexlify(adv_addr_big_endian), "\nadv_data: ", binascii.hexlify(adv_data),"\nble_crc: ", binascii.hexlify(ble_crc), "\nRSSI", rssi, "\nChannel", bchannel, "\nFCSOK",fcsok)

            ble_pdu_pl_len0 = len(ble_pdu_payload)
            
            #RxAdd (1 bit) | TxAdd (1 bit) | RFU (2 bit)  | Tipo PDU (4 bit) | RFU (2 bit) | Lunghezza (6 bit)
            RXrnd = (ble_pdu_head[0] & 0x80) > 0
            TXrnd = (ble_pdu_head[0] & 0x40) > 0
            ble_pdu_type = ble_pdu_head[0] & 0x0F
            ble_pdu_pl_len = ble_pdu_head[1] & 0x3F
            
            if(ble_pdu_pl_len0 != ble_pdu_pl_len): print("len ERROR")

            adv_data_len = len(adv_data)
            
            if(adv_data_len >= 27):
                uuid = struct.unpack_from("<H",adv_data[2:4])[0]  #'H' unsigned short (2)
            else:
                uuid = 0
            
            print_packet = False
#            if(ble_pdu_type == 6):
#                print_packet = True
            
            if((ble_pdu_type == 6) & (uuid == 0xfd6f)):
                rolling_code = adv_data[8:]
                
                #print(last_rolling_code)
                if(rolling_code != last_rolling_code):
                    last_rolling_code = rolling_code
                    ts_change = '{0:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()) # '{0:%Y-%m-%d %H:%M:%S}'
                    print("\n%s IMMUNI rolling_code changed: %s  adv_addr: %s  RSSI: %d  FCS: %s" % (ts_change, binascii.hexlify(rolling_code), binascii.hexlify(adv_addr), rssi, fcsok))
                    
                
            if(print_packet == True):
                print("%10d: %s %s %s    %d  %d  %s" % (timestamp, binascii.hexlify(ble_aa), binascii.hexlify(ble_pdu), binascii.hexlify(ble_crc), rssi, bchannel, fcsok))
                
                print ("ble_pdu_head = ",''.join('{:02X}'.format(x) for x in ble_pdu_head))
                print ("ble_pdu_payload = ",''.join('{:02X}'.format(x) for x in ble_pdu_payload))
                print ("ble_pdu_pl_len0",ble_pdu_pl_len0)
                print ("TXrnd",TXrnd)
                print ("RXrnd",RXrnd)
                print ("ble_pdu_type = %i" % ble_pdu_type)
                print ("ble_pdu_pl_len = %i" % ble_pdu_pl_len)
                print("adv_addr = 0x",''.join('{:02X}'.format(x) for x in adv_addr[::-1]))
                print("adv_data = ",''.join('{:02X}'.format(x) for x in adv_data))
                
                print("uuid = %04X" % uuid)
                print("uuid = %d" % uuid)
                print("0xfd6f = %d" % 0xfd6f)
                        
            #print("TODO: do something with packet")
#            packet = SniffedPacket(macPDU, timestamp)
#            for handler in handlers:
#                handler.handleSniffedPacket(packet)

    snifferDev = CC2540EMK(handlerDispatcher, channel)    
    
    def printHelp():
        print("TODO: help")
#        h = StringIO()
#        deviceStr = str(snifferDev)
#        h.write(deviceStr + '\n')
#        h.write('-' * len(deviceStr) + '\n')
#        h.write('Commands:\n')
#        h.write('c: Print current RF Channel\n')
#        h.write('h,?: Print this message\n')
#        h.write('[11,26]: Change RF channel\n')
#        h.write('s: Start/stop the packet capture\n')
#        h.write('d: Toggle frame dissector\n')
#        h.write('a*: Set an annotation (write "a" to remove it)\n')
#        h.write('p: Print all capture packets\n')
#        h.write('q: Quit')
#        h = h.getvalue()
#        print(h)

#    if args.rude is False:
#        printHelp()

    def f1():
        try:
            print("\n\n\nusb.core.find(backend=use_backend, idVendor=0x0451, idProduct=0x16b3)")
            dev = usb.core.find(backend=use_backend, idVendor=0x0451, idProduct=0x16b3) #idVendor=0x1a86, idProduct=0x7523  idVendor=0x0451, idProduct=0x16b3
        except usb.core.USBError:
            raise OSError(
                "Permission denied, you need to add an udev rule for this device",
                errno=errno.EACCES)
        if dev is None:
            raise IOError("Device not found")    
        else:    
            print("\n\n\npprint(dev)")
            pprint(dev)
            
            print("\n\n\npprint(dev._get_full_descriptor_str())")
            print(dev._get_full_descriptor_str() + "\n")
               
            print("\n\n\ndev.set_configuration()")        
            dev.set_configuration()
            
        print("\n\n\nname:") 
        name = dev.product or "Default name"
        print(name) 
        
        print("\n\n\nGET_IDENT = 0xc0") 
        #                                           GET_IDENT = 0xc0
        ident = dev.ctrl_transfer(CC2540EMK.DIR_IN, CC2540EMK.GET_IDENT, 0, 0, 256)  # get identity from Firmware command
        print(ident)
        
        #SmartRF fa ancora una set_configuration e poi si ferma fino allo start sniff
        

        print("\n\n\nSET_POWER = 0xc5") 
        # power on radio, wIndex = 4
        #                                     SET_POWER = 0xc5
        dev.ctrl_transfer(CC2540EMK.DIR_OUT, CC2540EMK.SET_POWER, wIndex=4)

        while True:
            print("\n\n\nGET_POWER = 0xc6") 
            # check if powered up
            #                                                        GET_POWER = 0xc6
            power_status = dev.ctrl_transfer(CC2540EMK.DIR_IN, CC2540EMK.GET_POWER, 0, 0, 1)
            if power_status[0] == 4: break
            time.sleep(0.1)

        print("\n\n\nSET_CHAN = 0xd2  0")
        #self.set_channel(channel)            
        # set channel command
        #                                    SET_CHAN = 0xd2  # 0x0d (idx 0) + data)0x00 (idx 1)
        dev.ctrl_transfer(CC2540EMK.DIR_OUT, CC2540EMK.SET_CHAN, 0, 0, [channel])
        print("\n\n\nSET_CHAN = 0xd2  1")
        dev.ctrl_transfer(CC2540EMK.DIR_OUT, CC2540EMK.SET_CHAN, 0, 1, [0x00])       
             

                    
            
    try:
        while 1:
            # if snifferDev.isSniffing():
            #     print_packets()
            if False:
                print("TODO: Add rude")
#            if args.rude is True:
#                if snifferDev.isRunning() is False:
#                    snifferDev.start()
            else:
                try:
                    # use the Windows friendly "raw_input()", instead of select()
                    cmd = input('')
                    

                    if '' != cmd:
#                        logger.debug('User input: "%s"' % (cmd, ))
                        print('User input: "%s"' % (cmd, ))
                        if cmd in ('h', '?'):
                            printHelp()
                        elif cmd == '1':
                            # test 1
                            print("one_start")
                            snifferDev.one_start()
                        elif cmd == '2':
                            # test 2
                            print("one_read")
                            snifferDev.one_read()
                        elif cmd == '3':
                            # test 3
                            print("one_stop")
                            snifferDev.one_stop()

                        elif cmd == 'd':
                            print("dump_stats()")
                            dump_stats()

                        elif cmd == 'i':
                            print("re-init hw")
                            snifferDev.init_hw()

                        elif cmd == 'q':
#                            logger.info('User requested shutdown')
                            sys.exit(0)
#                        elif cmd == 's':
#                            if snifferDev.isRunning():
#                                snifferDev.stop()
#                                print("Stopped")
#                            else:
#                                snifferDev.start()
#                                print("Started")
#                        elif 'a' == cmd[0]:
#                            if 1 == len(cmd):
#                                packetHandler.setAnnotation('')
#                            else:
#                                packetHandler.setAnnotation(cmd[1:].strip())
                        elif cmd == 's':
                            if snifferDev.isSniffing():
                                snifferDev.stop_sniff()
                                print("Stopped")
                            else:
                                snifferDev.start_sniff()
                                print("Started")
                        elif int(cmd) in range(37, 39):
                            snifferDev.set_channel(int(cmd))
                            print('Sniffing in channel: %d' % 
                                  (snifferDev.get_channel(), ))
                            #print('Sniffing in channel: %d' % (int(cmd), ))
                        else:
                            print("Channel must be from 37 to 39 inclusive.")
                except ValueError:
                    print('Unknown Command. Type h or ? for help')
                except UnboundLocalError:
                    # Raised by command 'n' when -o was specified at command line
                    pass

    except (KeyboardInterrupt, SystemExit):
        print('Shutting down')
#        logger.info('Shutting down')
#        if snifferDev.isRunning():
#            snifferDev.stop()
#        dump_stats()
        sys.exit(0)
