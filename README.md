# EMEA-CATS-Packet-Trace-PCAP

This program generates PCAP (Packet Capture) files from the outputs of the Cisco IOS-XE Datapath Packet Trace feature. The packet-trace feature is available in Cisco IOS-XE version 3.10 and later releases on the QFP (Quantum Flow Processor) based routing platforms, which include the ASR1000, ISR4000, ISR1000, Catalyst 1000, Catalyst 8000, CSR1000v, and Catalyst 8000v series routers. 

For a more detailed description and examples of this feature, please check the link below:
[Troubleshoot with the IOS-XE Datapath Packet Trace Feature](https://www.cisco.com/c/en/us/support/docs/content-networking/adaptive-session-redundancy-asr/117858-technote-asr-00.html)

The outputs that are processed by this utility program are those from the following command:

```
Router# show platform packet-trace packet all decode
```

The result of the command will be a list of the capture packets and, potentially, the hexadecimal decoded packet. We use the hexadecimal representation to generate a PCAP file that can be analyzed in applications such as Wireshark. This makes it much easier to analyze and to use this feature to troubleshoot network problems.

## Example of using Cisco IOS-XE Datapath Packet Trace

1. Create an ACL to match intended traffic:

```
Router# configure terminal
Router(config)# ip access-list extended ACL_TAC_PT
Router(config-ext-nacl)# permit ip any host 10.0.0.1
Router(config-ext-nacl)# permit ip host 10.0.0.1 any
```

2. Set up the conditions and the parameters for the Packet Trace Capture:

```
Router# debug platform condition ipv4 access-list ACL_TAC_PT both
Router# debug platform packet-trace packet 256 fia-trace
Router# debug platform packet-trace copy packet both l2
```

The first condition will only match packets that are permitted by the ACL_TAC_PT ACL. The second condition will limit the number of captured packets to 256 and will also collect a trace of the Feature Invocation Array (FIA) to see how the packets are getting internally processed by the QFP. Finally, the third condition will include the hexadecimal decode of the packet including the Layer 2 frame. 

3. Start the Packet Trace Capture and Stop after collecting enough packets:

```
Router# debug platform condition start

... wait ...

Router# debug platform condition stop
```

4. Print and store the outputs:

```
Router# show platform packet-trace packet all decode
```

The results of this last command can be stored in a file for PCAP conversion through this tool.

## How to use

```
usage: pt_process [-v | --version] [-h | --help] <input-packet-trace-file> [-s | --split]
```

Let's go over the available options:

<style>
table th:first-of-type {
    width: 3%;
}
table th:nth-of-type(2) {
    width: 10%;
}
table th:nth-of-type(3) {
    width: 50%;
}
table th:nth-of-type(4) {
    width: 30%;
}
</style>

Option                         | Description
-------------------------------|--------------------
\-\-help \-h          | Display the help message explaining how to use the script.
\-\-version \-v       | Display the current software version.
\-\-split \-s         | Separates packets into multiple PCAP files according to their traffic flow: ingress, egress, punted. Otherwise, all packets are stored in a single file.
