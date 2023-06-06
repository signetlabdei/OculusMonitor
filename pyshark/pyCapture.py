# PyShark documentation: http://kiminewt.github.io/pyshark/
# run example: python pyCapture.py test 2.8.2 684336


import pyshark
import csv
import datetime
from progress.bar import IncrementalBar
import argparse


# Construct the argument parser
ap = argparse.ArgumentParser()

# Add the arguments to the parser
ap.add_argument("fileName", help="pcap file name")
ap.add_argument("vrAddress", help="address of the VR from the pcap")
ap.add_argument("totPackets", help="Total number of packets on the pcap file", type=int)

args = ap.parse_args()

# update accordingly
inputTrace = args.fileName + ".pcapng"
outputFile = args.fileName + "_filtered.csv"
capture = pyshark.FileCapture(inputTrace) #Input .pcap file
srcAddress = "host" # Computer Address
dstAddress = args.vrAddress # VR Address
totPackets = args.totPackets # Total number of packets on the .pcap file

def timestamp(dt):
    epoch = datetime.datetime.utcfromtimestamp(0)
    return (dt - epoch).total_seconds() * 1000.0

with IncrementalBar('Processing...', max = totPackets, suffix='%(percent).1f%% - %(elapsed)ds') as bar:
    with open(outputFile, "w") as output:
        header = "time,size,direction \n"
        output.write(header)
        for packet in capture:
            if packet.layers[0].dst == dstAddress and packet.layers[0].src == srcAddress:
                sniffTime = packet.sniff_timestamp
                packetSize = packet.captured_length
                direction = "DL"
                addTrace = f"{sniffTime},{packetSize},{direction} \n"
                output.write(addTrace)
            elif packet.layers[0].dst == srcAddress and packet.layers[0].src == dstAddress:
                sniffTime = packet.sniff_timestamp
                packetSize = packet.captured_length
                direction = "UL"
                addTrace = f"{sniffTime},{packetSize},{direction} \n"
                output.write(addTrace)
            bar.next()
        output.close()
