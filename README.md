# EMEA-CATS-Packet-Trace-PCAP

This program generates PCAP (Packet Capture) files from the outputs of the Cisco IOS-XE Datapath Packet Trace feature.

## How to use

```
usage: pt-process [-v | --version] [-h | --help] <input-packet-trace-file> [-s | --split]
```

Let's go over the available options:

- Version: will print the software version of the tool being used.
- Help: will print the above usage explanation.
- Split: will split the packets into multiple files according to their traffic flow (ingress, egress, punted). Otherwise, it will store everything in a single file, following order of arrival.

## Notes on Deployment

The goal behind this tool is for it to work in a similar fashion as to "Spotlight". When spotlight detects a system report, it will jump in and decode the tracelogs, and it will create a new file in the case attachments. With this tool, we could try to detect the "show platform packet-trace packet all decode" in files in the attachments and generate a PCAP file out of it. Could this be done with IC?


We can also explore a few other options. For instance, this tool can be added to the engineering server. It's a simple python tool, so there's not much work on just copying the code. I don't see a lot of use cases for this, but it's easy to do.

And we can also add it as a script in BDB Scripts, like this one: https://scripts.cisco.com/ui/use/QFP_Parser_py3

As for a roadmap, I think that it's better to start with the BDB Scripts, as that's easy to use and can have many use cases.

## Example of using IOS-XE Packet Trace

To generate such outputs, one may use the example below:

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

## Thought Process Regarding Splitting the Outputs

Considering the following diagram:

```
           +--------------+
 Gig 0/0/1 |    Router    | Gig 0/0/2
-----------+              +-----------
           |              |
           +--------------+
```

We can configure the Packet Trace capture based on Gig 0/0/1 or Gig 0/0/2 interface, and we could split the data into the following files:

- ingress.pcap
- egress.pcap

But we can also configure the capture based on an ACL. In this case we can also split it based on ingress and egress, but would it make sense? Because we would have multiple possible interfaces being used as ingress and egress. I think we should include this as an option.

## Different Directions Traffic Can Take

Traffic can assume the following directions:

- Ingress from one interface and egress: This will generate an ingress and an egress packet based on both decodes.
- Injected and then punted: This will consider the out/egress decode and will be saved in the "punted" output file.
- Ingress and then punted: This will be saved in the ingress file, and will consider the ingress decode.
- Injected and then egress: This will be saved on the egress file, considering the egress decode.

The first direction will generate an ingress and an egress packet.

## TODO

Development:

- (Done) Generate two PCAP files for each output, separating ingress from egress traffic.
- (Done) Stop asking for the inputs and use arguments instead.
- (Done) Test with more outputs to make sure code is working as intended.
- (Done) Add another PCAP output file for punted traffic.

Deployment:

- (Done) Implement as a BDB Script.
- Add to the Engineering Server.
- Add as an IC Tool such as Spotlight.
