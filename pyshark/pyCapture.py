# PyShark documentation: http://kiminewt.github.io/pyshark/

import pyshark
import csv
import datetime
from progress.bar import Bar

def timestamp(dt):
    epoch = datetime.datetime.utcfromtimestamp(0)
    return (dt - epoch).total_seconds() * 1000.0

capture = pyshark.FileCapture('test.pcap')
csvFile = "trace2.csv"
srcAddress = "host"
dstAddress = "2.8.2"
totPackets = 684336

with Bar('Processing...', max = totPackets) as bar:
    with open(csvFile, "w") as output:
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
