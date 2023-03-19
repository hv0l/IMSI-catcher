#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
from datetime import datetime
from pathlib import Path

from scapy.all import sniff


def find_assignment(packet):
    """
    Extracts SDCCH, Subchannel, Timeslot, HoppingChannel, and ARFCN from GSM packets.
    """
    if "GSM" in packet:
        gsm_packet = packet["GSM"]
        if gsm_packet:
            if gsm_packet.channel_type != 0:  # Channel Type != BCCH (0)
                if gsm_packet.msg_type == 1:  # Dedicated mode or TBF: This message assigns a dedicated mode resource (0)
                    sdcch = gsm_packet.sdcch
                    subchannel = gsm_packet.subchannel
                    timeslot = gsm_packet.timeslot
                    hopping_channel = "yes" if gsm_packet.hopping_channel else "no"
                    arfcn = gsm_packet.arfcn
                    return sdcch, subchannel, timeslot, hopping_channel, arfcn
                elif gsm_packet.msg_type == 2:  # Dedicated mode or TBF: This message assigns an uplink TBF or is the second message of two in a two-message assignment of an uplink or downlink TBF (1)
                    timeslot = gsm_packet.timeslot
                    arfcn = gsm_packet.arfcn
                    return "-", "-", timeslot, "-", arfcn
    return None


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Display SDCCH, Subchannel, Timeslot, HoppingChannel, and ARFCN for GSM packets.")
    parser.add_argument("-i", "--iface", dest="iface", default="lo", help="Interface (default : lo)")
    parser.add_argument("-p", "--port", dest="port", default="4729", type=int, help="Port (default : 4729)")
    parser.add_argument("-t", "--time", dest="time", default=60, type=int, help="Time to run the sniffer in seconds (default: 60)")
    parser.add_argument("-o", "--output", dest="output", help="Output file path (default: stdout)")
    args = parser.parse_args()

    # Run the sniffer
    start_time = datetime.now()
    results = []
    sniff(iface=args.iface, filter="port {} and not icmp and udp".format(args.port), prn=lambda x: results.append(find_assignment(x)), timeout=args.time)

    # Print or save the results
    if args.output:
        with Path(args.output).open("w") as f:
            f.write("SDCCH\t; Subchannel\t; Timeslot\t; HoppingChannel\t; ARFCN\n")
            for res in results:
                if res:
                    f.write("{}\t; {}\t\t; {}\t\t; {}\t\t\t; {}\n".format(*res))
    else:
        print("SDCCH\t; Subchannel\t; Timeslot\t; HoppingChannel\t; ARFCN")
        for res in results:
            if res:
                print("{}\t; {}\t\t; {}\t\t; {}\t\t\t; {}".format(*res))

    # Print the elapsed time
    end_time = datetime.now()
    elapsed_time = end_time - start_time
    print("Elapsed time: {}".format(elapsed_time))


if __name__ == "__main__":
    main()
