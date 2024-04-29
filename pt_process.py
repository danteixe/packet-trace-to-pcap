# Copyright (c) 2023-2024 Cisco Systems, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
#
#   Redistributions in binary form must reproduce the above
#   copyright notice, this list of conditions and the following
#   disclaimer in the documentation and/or other materials provided
#   with the distribution.
#
#   Neither the name of the Cisco Systems, Inc. nor the names of its
#   contributors may be used to endorse or promote products derived
#   from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.

"""
This is an utility program that analyzes the outputs of the following
Cisco IOS-XE command:

show platform packet-trace packet all decode

The outputs are parsed and saved in PCAP files for easier analysis
of the packets captured with the Cisco IOS-XE Datapath Packet
Trace feature.
"""

import sys # input/output
import re # regex
import logging

import os.path

from scapy.all import wrpcap
from scapy.layers.l2 import Ether

# Patterns for parsing the text file

PATTERN_FIRST_LINE = r"^Packet\: [0-9]+.*$"
PATTERN_EOF = r"^$"
PATTERN_IOSD_PATH_FLOW = r"^IOSd Path Flow\: Packet\: [0-9]+.*$"
PATTERN_COPY_IN = r"^Packet Copy In.*$"
PATTERN_COPY_OUT = r"^Packet Copy Out.*$"
PATTERN_PATH_TRACE = r"^Path Trace.*$"
PATTERN_SUMMARY = r"^Summary.*$"
PATTERN_L2 = r"^\s*ARPA\n$"
PATTERN_L3 = r"^\s*IPv(4|6)\n$"
PATTERN_L3_ONLY = r"^\s*Unable to decode layer 2 trying to skip to layer 3.*$"

PATTERN_COPY_DECODE_ALTED = r"^\s*Decode\s+halted\s+\-\s+end\s+of\s+packet\s+copy\s+reached.*$"

PATTERN_PUNT_STATE = r"\s*PUNT\s+[0-9]+.*"

PATTERN_INJECT_INGRESS = r"INJ\.[0-9]"
PATTERN_INJECT_EGRESS = r"internal0\/0\/rp\:[0-9]"
PATTERN_COPY_HEX = r"^(\s+[0-9a-fA-F]{2,})+$"

DIRECTION_OUT_L3 = "out_l3"
DIRECTION_IN_L3 = "in_l3"
DIRECTION_BOTH_L3 = "both_l3"
DIRECTION_OUT_L2 = "out_l2"
DIRECTION_IN_L2 = "in_l2"
DIRECTION_BOTH_L2 = "both_l2"

# Patterns for the view component

PATTERN_VIEW_HELP = r"^(-h|--help)$"
PATTERN_VIEW_VERSION = r"^(-v|--version)$"
PATTERN_VIEW_SPLIT = r"^(-s|--split)$"
PATTERN_VIEW_OPTION_GENERIC = r"^\-{1,2}.*$"

# Bogus dummy frame headers

DUMMY_L2_FRAME = "005300aaaaaa 005300bbbbbb 0800"
DUMMY_L2_FRAME_DOT1Q = "0053aaaaaa 005300bbbbbb 00000001 0800"

logger = logging.getLogger()
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s', datefmt='%Y-%m-%dT%T')
consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(formatter)
consoleHandler.setLevel(logging.INFO)
logger.addHandler(consoleHandler)

def parse_packets(filename):
    packet = {}
    packets = []

    # Used to skip to the next packet, because the current packet
    # cannot be parsed (e.g., doesn't have a hexadump).
    skip = False
    stop = False

    with open(filename, "r", encoding="utf-8") as file:
        while not stop:
            line = file.readline()

            # EOF hit or first line
            if not line or re.match(PATTERN_FIRST_LINE, line):
                # Store previous packet
                if packet:

                    # Check if packet is valid
                    # It only needs one of the decodes
                    if ("copy_in" not in packet and "copy_out" not in packet):
                        logger.info(packet)
                        logger.info("Packet doesn't have a decode (or can't be decoded).")
                    else:
                        packets.append(packet)

                if not line:
                    stop = True
                else:
                    # Begin work on current packet
                    packet = {}
                    packet["id"] = len(packets)
                    skip = False

            elif skip: # Skip this packet until the first line is read
                # Do nothing
                pass

            elif re.match(PATTERN_SUMMARY, line):
                packet["ingress"] = file.readline().split(":", 1)[1].strip()
                packet["egress"] = file.readline().split(":", 1)[1].strip()
                packet["state"] = file.readline().split(":", 1)[1].strip()
                file.readline()
                packet["start_ns"] = file.readline().split(":", 1)[1].split("ns")[0].strip()
                packet["stop_ns"] = file.readline().split(":", 1)[1].split("ns")[0].strip()

                #if re.match(PATTERN_PUNT_STATE, packet["state"]):
                #    logger.info("Deteted injected packet (PUNT 24) that will be ignored.")
                #    packet = {}
                #    skip = 1

            elif re.match(PATTERN_COPY_IN, line):
                packet["copy_in"] = ""

                if "ingress" in packet and re.match(PATTERN_INJECT_INGRESS, packet["ingress"]):
                    continue
                    # If the ingress interface is INJ, let's ignore the ingress packet decode.
                    # We'll only consider the egress decode.
                    # With an INJ, the output decode will either be dropped,
                    # sent through and interface, or punted, so the egress
                    # decode is what will matter.

                else:
                    last_pos = file.tell()
                    copy_line = file.readline()

                    while re.match(PATTERN_COPY_HEX, copy_line):
                        packet["copy_in"] += " " + copy_line.replace("\n", "")
                        last_pos = file.tell()
                        copy_line = file.readline()

                    file.seek(last_pos)
                    aux_header = file.readline()
                    file.seek(last_pos)


                    if (re.match(PATTERN_L3_ONLY, aux_header) or
                        re.match(PATTERN_INJECT_INGRESS, packet["ingress"])):
                        packet["direction"] = DIRECTION_IN_L3

                    elif re.match(PATTERN_L3, aux_header):
                        if (packet.get("direction") is not None
                            and packet["direction"] == DIRECTION_OUT_L3):
                            packet["direction"] = DIRECTION_BOTH_L3
                        else:
                            packet["direction"] = DIRECTION_IN_L3
                    else:
                    #if re.match(PATTERN_L2, aux_header):
                    # If there's a L2 pattern or none at all, just treat
                    # it like there's L2 information on the decode
                        if (packet.get("direction") is not None
                            and packet["direction"] == DIRECTION_OUT_L2):
                            packet["direction"] = DIRECTION_BOTH_L2
                        else:
                            packet["direction"] = DIRECTION_IN_L2


            elif re.match(PATTERN_COPY_OUT, line):
                packet["copy_out"] = ""

                # Let's check if the packet was punted. If it was, then the first line of 
                # the decode will contain internal punted information
                aux_header = ""
                ignore = 0

                # If the packet is punted, but it came from a regular ingress interface,
                # then we must ignore the out decode and only consider the in decode.

                if (re.match(PATTERN_PUNT_STATE, packet["state"])
                    and not re.match(PATTERN_INJECT_INGRESS, packet["ingress"])):

                    ignore = 1

                elif re.match(PATTERN_PUNT_STATE, packet["state"]):
                    file.readline()
                    last_pos = file.tell()
                    copy_line = file.readline()

                    while re.match(PATTERN_COPY_HEX, copy_line):
                        packet["copy_out"] += " " + copy_line.replace("\n", "")
                        last_pos = file.tell()
                        copy_line = file.readline()

                    file.seek(last_pos)
                    aux_header = file.readline()

                    while (not re.match(PATTERN_L2, aux_header)
                        and not re.match(PATTERN_L3, aux_header)
                        and not re.match(PATTERN_COPY_DECODE_ALTED, aux_header)):

                        aux_header = file.readline()

                else:
                    last_pos = file.tell()
                    copy_line = file.readline()

                    while re.match(PATTERN_COPY_HEX, copy_line):
                        packet["copy_out"] += " " + copy_line.replace("\n", "")
                        last_pos = file.tell()
                        copy_line = file.readline()

                    file.seek(last_pos)
                    aux_header = file.readline()

                if (re.match(PATTERN_COPY_DECODE_ALTED, aux_header)
                    or ignore == 1):
                    pass
                    # Ignore the decode

                elif re.match(PATTERN_L3, aux_header):
                    if (packet.get("direction") is not None
                        and packet["direction"] == DIRECTION_IN_L3):
                        packet["direction"] = DIRECTION_BOTH_L3
                    else:
                        packet["direction"] = DIRECTION_OUT_L3

                else:
                # if re.match(PATTERN_L2, aux_header):
                # If there's a L2 pattern or none at all, just treat
                # it like there's L2 information on the decode
                    if (packet.get("direction") is not None
                        and packet["direction"] == DIRECTION_IN_L2):
                        packet["direction"] = DIRECTION_BOTH_L2
                    else:
                        packet["direction"] = DIRECTION_OUT_L2

            elif re.match(PATTERN_IOSD_PATH_FLOW, line):
                #parse_packets_iosd_path_flow(file, packet)
                # Ignore for the time being
                packet["iosd_path_flow"] = {}

    return packets

def internal_parse_packets_to_scapy(copy_packet_hex, timestamp_ns):
    """
    Take the packet hexdump from the "copy_in" and "copy_out" fields and 
    generate a scapy representation of the packet.

    Arguments:
    - copy_packet_hex: "copy_in" or "copy_out" hex dumps.
    - timestamp_ns: timestamp when the packet was received.
    """

    copy_packet_hex = copy_packet_hex.replace(' ', '')
    copy_packet_bytes = bytes.fromhex(copy_packet_hex)

    packet = Ether(copy_packet_bytes)

    timestamp_seconds = float(timestamp_ns) / 1000000000
    setattr(packet, "time", timestamp_seconds)

    return packet

def parse_packets_to_scapy(custom_packets):
    ingress_packets = []
    egress_packets = []
    punted_packets = []

    for custom_packet in custom_packets:
        timestamp_ns = custom_packet["start_ns"]

        logger.debug(custom_packet)

        if not "direction" in custom_packet:
            logger.error("Packet %d was not parsed because there's no \"direction\" attribute.",
                         custom_packet["id"])
            logger.error(custom_packet)
        elif (re.match(PATTERN_PUNT_STATE, custom_packet["state"])
            and re.match(PATTERN_INJECT_INGRESS, custom_packet["ingress"])):
            copy_packet_hex = custom_packet["copy_out"]
            packet = internal_parse_packets_to_scapy(copy_packet_hex, timestamp_ns)
            punted_packets.append(packet)

        elif custom_packet["direction"] == DIRECTION_OUT_L2:
            copy_packet_hex = custom_packet["copy_out"]
            packet = internal_parse_packets_to_scapy(copy_packet_hex, timestamp_ns)
            egress_packets.append(packet)

        elif custom_packet["direction"] == DIRECTION_IN_L2:
            copy_packet_hex = custom_packet["copy_in"]
            packet = internal_parse_packets_to_scapy(copy_packet_hex, timestamp_ns)
            ingress_packets.append(packet)

        elif custom_packet["direction"] == DIRECTION_OUT_L3:
            copy_packet_hex = DUMMY_L2_FRAME + custom_packet["copy_out"]
            packet = internal_parse_packets_to_scapy(copy_packet_hex, timestamp_ns)
            egress_packets.append(packet)

        elif custom_packet["direction"] == DIRECTION_IN_L3:
            copy_packet_hex = DUMMY_L2_FRAME + custom_packet["copy_in"]
            packet = internal_parse_packets_to_scapy(copy_packet_hex, timestamp_ns)
            ingress_packets.append(packet)

        elif custom_packet["direction"] == DIRECTION_BOTH_L2:
            copy_packet_hex_egress = custom_packet["copy_out"]
            egress_packet = internal_parse_packets_to_scapy(copy_packet_hex_egress, timestamp_ns)
            egress_packets.append(egress_packet)

            copy_packet_hex_ingress = custom_packet["copy_in"]
            ingress_packet = internal_parse_packets_to_scapy(copy_packet_hex_ingress, timestamp_ns)
            ingress_packets.append(ingress_packet)

        elif custom_packet["direction"] == DIRECTION_BOTH_L3:
            copy_packet_hex_egress = DUMMY_L2_FRAME + custom_packet["copy_out"]
            egress_packet = internal_parse_packets_to_scapy(copy_packet_hex_egress, timestamp_ns)
            egress_packets.append(egress_packet)

            copy_packet_hex_ingress = DUMMY_L2_FRAME + custom_packet["copy_in"]
            ingress_packet = internal_parse_packets_to_scapy(copy_packet_hex_ingress, timestamp_ns)
            ingress_packets.append(ingress_packet)

        else:
            logger.error("Packet %d was not parsed due to abnormal direction attribute: %s",
                         custom_packet["id"], custom_packet["direction"])

    return {
        "ingress_packets": ingress_packets,
        "egress_packets": egress_packets,
        "punted_packets": punted_packets
    }

def write_outputs(input_filename, split, packets):
    """
    Arguments:
    - input_filename: filename used to extract the packets.
    - split: whether to split the packets into multiple files.
    - packets: parsed packets from the input_filename file.

    The function will save the packets in an output PCAP-formatted
    file, or in multiple files if desired. The file will only be
    created if the list of packets is not empty.
    """

    ingress_packets = packets["ingress_packets"]
    egress_packets = packets["egress_packets"]
    punted_packets = packets["punted_packets"]

    if split:
        temp = input_filename.rsplit(".", 1)[0]
        output_ingress  = temp + "_ingress.pcap"
        output_egress   = temp + "_egress.pcap"
        output_punted   = temp + "_punted.pcap"

        if ingress_packets:
            logger.info("Saving ingress packets to %s.", output_ingress)
            wrpcap(output_ingress, ingress_packets)
        else:
            logger.info("Empty ingress packet list. Not possible to save %s.", output_ingress)

        if egress_packets:
            logger.info("Saving egress packets to %s.", output_egress)
            wrpcap(output_egress, egress_packets)
        else:
            logger.info("Empty egress packet list. Not possible to save %s.", output_egress)

        if punted_packets:
            logger.info("Saving punted packets to %s.", output_punted)
            wrpcap(output_punted, punted_packets)
        else:
            logger.info("Empty punted packet list. Not possible to save %s.", output_punted)
    else:
        packets = ingress_packets + egress_packets + punted_packets
        packets.sort(key=lambda x: x.time)

        temp = input_filename.rsplit(".", 1)[0]
        output_file = temp + "_output.pcap"

        if packets:
            logger.info("Saving packets to %s.", output_file)
            wrpcap(output_file, packets)
        else:
            logger.info("Empty packet list. Not possible to save %s.", output_file)

def view_show_help():
    """Print the help string with how to use the script."""
    print("usage: pt-process [-v | --version] [-h | --help] <input-packet-trace-file> [-s | --split]")
    print("")
    print(" -v or --version     Print version information.")
    print(" -h or --help        Print this message.")
    print(" -s or --split       Separate the packets into multiple PCAP files based on")
    print("                     being either ingress, egress, or punted packets.")

def view_show_version():
    """Print the software version."""
    print("pt-process version 1.1.0")

def view_process():
    """ Run the "View" processor, that parses the inputs
    of the command line command to understand if we should:
    - Display the "help" template.
    - Display the current software version.
    - Parse an input file and convert it into a PCAP.
    """

    len_arg = len(sys.argv)

    # There should be at least 2 arguments: the name of the script and a
    # script argument. If there's not, print the help string.

    if len_arg < 2:
        view_show_help()
        return None

    argument = sys.argv[1]

    if re.match(PATTERN_VIEW_HELP, argument):
        view_show_help()
        return None

    if re.match(PATTERN_VIEW_VERSION, argument):
        view_show_version()
        return None

    # Check if the filename is valid
    filename = argument

    if not os.path.isfile(filename):
        raise FileNotFoundError("File Not Found: " + filename)

    if len_arg > 2:
        split_argument = sys.argv[2]

        if re.match(PATTERN_VIEW_SPLIT, split_argument):
            return { "filename": filename, "split": True}

    return { "filename": filename, "split": False }

def main():
    """ 
    1. Gather the data from the log file.
    2. Organize the information per packet into an array.
    3. Populate the metadata for each packet element in the array.
    4. Save the packets in a pcap file based on the decode.
    """

    parsed_args = view_process()
    logger.setLevel(logging.WARN)

    if parsed_args:
        filename = parsed_args["filename"]
        split = parsed_args["split"]

        logger.info("----   Starting process for %s ----", filename)

        logger.info("1 - Reading packets ")
        custom_packets = parse_packets(filename)

        logger.info("2 - Parsing packets ")
        packets = parse_packets_to_scapy(custom_packets)

        logger.info("3 - Saving outputs ")
        logger.info(filename)

        write_outputs(filename, split, packets)


if __name__ == "__main__":
    main()
    
