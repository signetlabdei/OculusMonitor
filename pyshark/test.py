# PyShark documentation: http://kiminewt.github.io/pyshark/

# Allow Wireshark to be runned without sudo mode.
# $ sudo apt-get install wireshark
# $ sudo dpkg-reconfigure wireshark-common 
# $ sudo usermod -a -G wireshark $USER
# $ newgrp wireshark

import pyshark
import csv
import datetime

def timestamp(dt):
    epoch = datetime.datetime.utcfromtimestamp(0)
    return (dt - epoch).total_seconds() * 1000.0

capture = pyshark.LiveCapture (interface = 'enp1s0')
timeout = 1200
csvFile = "trace.csv"
setBeginTime = False

with open(csvFile, "w") as output:
    header = "time,size \n"
    output.write(header)
    capture._packets
    beginTime = datetime.datetime.now ()
    for packet in capture.sniff_continuously():
        if (packet.sniff_time.microsecond != 0):
            seconds = packet.sniff_time.second + packet.sniff_time.microsecond / 10**6
            seconds = round (seconds, 6)
            date = f"{packet.sniff_time.year}-{packet.sniff_time.month}-{packet.sniff_time.day} {packet.sniff_time.hour}:{packet.sniff_time.minute}:{seconds}"
            packetTime = datetime.datetime.strptime(date, '%Y-%m-%d %H:%M:%S.%f')
        else:
            seconds = packet.sniff_time.second
            date = f"{packet.sniff_time.year}-{packet.sniff_time.month}-{packet.sniff_time.day} {packet.sniff_time.hour}:{packet.sniff_time.minute}:{seconds}"
            packetTime = datetime.datetime.strptime(date, '%Y-%m-%d %H:%M:%S')

        if not setBeginTime:
            beginTime = packetTime
            setBeginTime = True

        if ((packetTime-beginTime).total_seconds() > timeout):
          break
        sniffTime = packet.sniff_timestamp
        packetSize = packet.captured_length
        addTrace = f"{sniffTime},{packetSize} \n"
        output.write(addTrace)
    output.close()
