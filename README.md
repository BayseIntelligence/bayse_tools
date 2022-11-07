# Bayse Tools
The `bayse-tools` package provides functionality that allows users to convert a growing number of network flow formats 
into the lightweight BayseFlow format. Doing so offers the ability to interact with the Bayse labeling and 
knowledgebase functionality, which provides detailed insights about how your systems are communicating with the 
Internet and your internal devices. For more information about use cases, explore our 
[Use Cases](https://bayse.io/resources/use-cases) online.  

## Installation
Note that this package requires libpcap-dev to be installed on your system. Please use your system's package manager
(such as apt on Ubuntu) to install libpcap-dev:

`sudo apt-get install libpcap-dev`

While Windows isn't yet supported due to issues with underlying libraries (specifically pcapy), we'd welcome anyone 
who wants to document the steps to make it work. At the very minimum, you will need the following:

* A C++ compiler. Microsoft Visual Studio Build Tools is known to work.
* Npcap's SDK, which is a replacement for the WinPCAP developer's kit.

To install the bayse-tools package, simply type the following:

`pip install bayse-tools`


## Available Modules
There are two modules available within this package. Details about each are below.

### A. Standalone Converter
module name: `converter`

This module allows you to convert captured network traffic from any of our [supported formats](#supported-file-formats) 
into unlabeled 
BayseFlows (BayseFlows without BayseFlow category labels). This is useful if you 
already have network telemetry that you'd like to enrich with our knowledgebase and labeling.

To import this module into your project, type the following:

`from bayse_tools.converter import convert`

#### Supported File Formats
Bayse currently supports conversion into BayseFlow format from the following formats:

| Format | Specific File Types                                |
|--------|----------------------------------------------------|
 | Packet Capture | `CAP`, `PCAP`, and `PCAPNG`                        |
 | Zeek  | `conn.log` and `dns.log` in `TSV` or `JSON` format |
 | Interflow | comma-separated list of `JSON` records             |

`?` If you have a format that you'd like us to support, please contact support at bayse [.] io.

#### Usage
To convert a Packet Capture into an unlabeled BayseFlow file, simply enter the following:

`convert.convert_pcap(<path_to_packet_capture>)`

To convert a Zeek `conn.log` into an unlabeled BayseFlow file, simply enter the following:

`convert.convert_zeek(<path_to_conn_log>, zeek_dnsfile_location=<optional_path_to_dns_log>)`

If you have (and would like to include) DNS information that was captured by Zeek, provide the `dns.log` in addition 
to the `conn.log`. Naming will be much enhanced by doing so.

To convert an Interflow log into an unlabeled BayseFlow file, simply enter the following:

`convert.convert_interflow(<path_to_interflow_log>)`

Any DNS Interflows should also be passed in within the Interflow log.

Note that there are MANY fields in Interflow that will not be a part of this converter, as they are not necessary to 
convert to BayseFlow. The log file is expected to contain a comma-separated list of Interflow records in JSON format.
For non-DNS records, below is an example Interflow record that includes only the fields we need:

    [{"timestamp": 1656517273641, "duration": 401, "_id": "6c0liABC8qtQm3loQr7H", "msg_class": "interflow_traffic", "srcip": "172.18.40.120", "srcport": 55503,"dstip": "142.251.40.65", "dstip_host": "ci3.googleusercontent.com", "dstport": 80, "proto_name": "tcp", "outbytes_total": 0, "inpkts_delta": 5, "outpkts_delta": 0, "inbytes_total": 17765}]


#### Plaintext Formats

Zeek and Interflow data is supported as JSON files in two formats:

1. Comma-Separated List of JSON records (**preferred**):

`[{json_record_1},{json_record_2}]`

2. One JSON record per line:

```
{json_record_1}
{json_record_2}
```

Moreover, Zeek also supports plaintext `TSV` (i.e. the OG). If you are converting plaintext logs, please make sure 
that your `conn.log` files have the following fields in the following order (Field # lines are annotations for 
clarity below and should **NOT** be included in the file):

```     
        Field #  1       2        3                 4               5
                ts      uid     id.orig_h       id.orig_p       id.resp_h
        Field #    6             7        8        9               10
                id.resp_p       proto   service duration        orig_bytes
        Field #     11              12              13              14
                resp_bytes      conn_state      local_orig      local_resp
        Field #     15             16      17               18             19
                missed_bytes    history orig_pkts       orig_ip_bytes  resp_pkts
        Field #       20              21
                resp_ip_bytes   tunnel_parents
```

An example of a flow line from the `conn.log` is as follows ("field #" lines are our annotation):
```
        Field #       1                        2                      3
                1601060272.439360       CC9S3G178KjzSMTGRk      192.168.100.224
        Field #   4             5        6       7       8          9
                 137    192.168.100.255 137     udp     dns     12.114023
        Field #  10     11    12      13     14      15      16       17
                1186    0     S0      -       -       0       D       23
        Field #  18     19      20      21
                1830    0       0       -
```

For dns.log files (again, if you're not using JSON), make sure that the file matches the following:
```
        Field #       1       2          3               4               5               6             7         8
                      ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       proto   trans_id
        Field #       9       10        11               12             13         14           15        16
                     rtt     query    qclass         qclass_name       qtype   qtype_name      rcode   rcode_name
        Field #      17      18      19      20      21        22         23        24
                     AA      TC      RD      RA      Z       answers     TTLs    rejected
```

Note that all field names are not used. If you do not have a field, please give it an appropriate default
value as defined by the [Zeek format](https://docs.zeek.org/en/master/logs/dns.html).


### B. Streaming BayseFlow Collector
module name: `streaming`

This module allows you to directly capture network traffic as unlabeled BayseFlows (BayseFlows without flow category 
labels). This is beneficial for a number of reasons:

BayseFlows are extremely lightweight, so you can actually do this continuously in the background without affecting 
system performance (i.e. you can collect network telemetry continuously on your endpoints)! BayseFlows have no 
identifying data, so you can avoid worrying about accidentally leaking information (URIs, passwords, keys, etc...)

To import this module into your project, type the following:

`from bayse_tools.streaming import streaming`

#### Usage
To capture BayseFlows continuously using this module from your project, enter the following (note that you'll need
to be root by default to capture packets):

`streaming.start(<interface_name>, <duration_in_seconds>, <optional_verbosity>)`

Note that the above will run in perpetuity, capturing packets from the interface you specified (such as *enp0s3* on
Ubuntu systems). Every time the specified duration you provided is reached (if you provide no value, it defaults to
300 seconds), a sample will be created, processed, and summarized. Providing the optional `is_verbose` value will 
print a small amount of information about the number of BayseFlows and its UUID.

## BayseFlow Format
The BayseFlow format is saved as a `.bf` file and is comprised of records containing that look like the following:

```
{
  "hash": "7e156c19e5cb412590f2a3d4400fb7f6",
  "trafficDate": "1617652286.24605",
  "fileName": "testCase5_oneFlowPlusLocalDNSIsProcessable_filtered.bf",
  "BayseFlows": [
    {
      "src": "192.168.86.245:22256",
      "dst": "192.168.86.1:53",
      "destinationNameSource": "original",
      "srcPkts": 1,
      "srcBytes": 44,
      "dstPkts": 1,
      "dstBytes": 76,
      "relativeStart": 0,
      "protocolInformation": "UDP",
      "identifier": "0",
      "duration": 0.074424
    },
    {
      "src": "192.168.86.245:63694",
      "dst": "contextualizedsecurity.com:443",
      "destinationNameSource": "passive",
      "srcPkts": 19,
      "srcBytes": 7552,
      "dstPkts": 24,
      "dstBytes": 11520,
      "relativeStart": 0.169868,
      "protocolInformation": "TCP",
      "identifier": "0",
      "duration": 7.556651
    }
  ]
}
```

Details about each field are as follows:

| Field Name               | Purpose                                                                                      | Derived How                                                                                                       |
|--------------------------|----------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------|
 | hash                     | helps to identify the BayseFlow file                                                         | randomly-generated                                                                                                |
| trafficDate              | identifies the time (as UTC epoch time in seconds.ms) the traffic capture started            | timestamps from initial file                                                                                      |
| fileName                 | name of the file                                                                             | based on name of input file                                                                                       |
| BayseFlows               | mapping of each flow to the BayseFlow format (fields below here are subfields of BayseFlows) | Combines packets/flows based on their 4-tuples                                                                    |
| --> src                  | identify the source of the flow                                                              | attempts to identify the true source based on how the flow is communicating; will add a DNS name if known         |
| --> dst                  | identify the destination of the flow                                                         | attempts to identify the true destination based on how the session is communicating; will add a DNS name if known |
| --> srcPkts              | number of packets from the source                                                            | counts how many packets seen in the input file from this source in this flow                                      |
| --> srcBytes             | number of bytes from the source                                                              | counts how many bytes were seen in the transport layer payloads (or ICMP data) from the source in this flow       | 
| --> dstPkts              | number of packets from the destination                                                       | counts how many packets seen in the input file from this destination in this flow                                 |
| --> dstBytes             | number of bytes from the destination                                                         | counts how many bytes were seen in the transport layer payloads (or ICMP data) from the destination in this flow  | 
| --> relativeStart        | how far into this file this flow began                                                       | time (as seconds.ms) from `trafficDate`                                                                           | 
| --> protocolInformation  | communicate any information about the transport layer protocol (or ICMP) seen                | transport layer reported by network layer                                                                         |
| --> identifier           | a way to tie the BayseFlow back to a flow in the original input format                       | unique_id for Zeek, TCP/UDP stream for Packet Captures                                                            |
| --> duration             | identify how long (seconds.ms) a flow lasted                                                 | start of first packet to end of last packet in flow                                                              |


## Troubleshooting

If you are having issues installing `bayse-tools`, here are some common issues:
* Your system does not have libpcap-dev installed. Please refer to the [Installation](#installation) steps above for 
  details.
* You have `pcapy` installed and are trying to use Python 3.10 or greater. In v1.0.1 of `bayse-tools`, we have moved 
  away from `pcapy` in favor of `pcapy-ng`. Please make sure to uninstall the former if it exists.

If nothing above helps or you have other questions, please reach out to us at support at bayse [.] io

## License
This software is provided under the MIT Software License. See the accompanying LICENSE file for more information.