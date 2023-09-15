# PyShark documentation: http://kiminewt.github.io/pyshark/
# run example: python pyCapture.py test 2.8.2 684336


import pyshark
# import csv
# import datetime
# from progress.bar import IncrementalBar
import argparse
import time
from pathlib import Path


# Construct the argument parser
ap = argparse.ArgumentParser()

# Add the arguments to the parser
ap.add_argument("folderName", help="pcap folder")
# ap.add_argument("fileName", help="pcap file name")
# ap.add_argument("vrAddress", help="address of the VR from the pcap")
# ap.add_argument("totPackets", help="Total number of packets on the pcap file", type=int)

args = ap.parse_args()

# update accordingly
folderName = Path(args.folderName)
n_files = len([f for f in folderName.iterdir() if ".pcapng" in f.name])
file_idx = 1
times = []
for fileName in folderName.iterdir():
    if fileName.suffix!=".pcapng":
        continue
    else:

        t0 = time.time()
        fileName = str(fileName.resolve()).strip(".pcapng")
        print(f"Running file {fileName} ({file_idx}/{n_files})")
        inputTrace = fileName+".pcapng"
        outputFile = str(fileName)+"_filtered.csv"
        # if Path(outputFile).exists():
        #     continue
        capture = pyshark.FileCapture(inputTrace) #Input .pcap file
        srcAddress = "host" # Computer Address
        # dstAddress = args.vrAddress # VR Address
        # totPackets = args.totPackets # Total number of packets on the .pcap file

        # def timestamp(dt):
        #     epoch = datetime.datetime.utcfromtimestamp(0)
        #     return (dt - epoch).total_seconds() * 1000.0

        # with IncrementalBar('Processing...', max = totPackets, suffix='%(percent).1f%% - %(elapsed)ds') as bar:

        dstAddress = ""
        i = 0
        for packet in capture:
            i = i + 1
            if int(packet.captured_length)>1052 and packet.layers[0].src == srcAddress:
                print(f"packet: {i} ({int(packet.captured_length)})") #,end="\r")
                currDstAddress = packet.layers[0].dst

                if currDstAddress!=dstAddress:
                    if dstAddress=="":
                        dstAddress = currDstAddress
                        continue
                    else:
                        raise AttributeError("The addresses do not match")
            if i>100:
                break
        print(f"the destination address is : {dstAddress}")
        # t1 = time.time()
        # elaps_time = (t1-t0)
        # times.append(elaps_time)
        # print(f"File {file_idx} took {elaps_time:.2f}. There are {n_files-file_idx} files left (approx. {sum(times)/len(times)*(n_files-file_idx):.2f})")  
 

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
                # bar.next()
            output.close()
        t1 = time.time()
        elaps_time = (t1-t0)
        times.append(elaps_time)
        print(f"File {file_idx} took {elaps_time}. There are {n_files-file_idx} files left (approx. {sum(times)/len(times)*(n_files-file_idx)})")
        file_idx = file_idx+1