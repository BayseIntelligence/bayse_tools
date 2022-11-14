{
  "hash": "848dbb9ec6bd4309b51a830d978b16f5",
  "trafficDate": "1654204899.899094",
  "fileName": "testCase23_ipv6_withDNS_and_icmpv6_filtered.bf",
  "BayseFlows": [
    {
      "src": "192.168.12.164:62239",
      "dst": "9.9.9.9:53",
      "destinationNameSource": "original",
      "srcPkts": 1,
      "srcBytes": 32,
      "dstPkts": 1,
      "dstBytes": 155,
      "relativeStart": 0.0,
      "protocolInformation": "UDP",
      "identifier": "0",
      "duration": 0.055491
    },
    {
      "src": "2607:fb90:d726:7b19:5cc5:a122:d8ae:24e6:58740",
      "dst": "r3.o.lencr.org:80",
      "destinationNameSource": "passive",
      "srcPkts": 84,
      "srcBytes": 14526,
      "dstPkts": 47,
      "dstBytes": 37302,
      "relativeStart": 0.112856,
      "protocolInformation": "TCP",
      "identifier": "0",
      "duration": 48.68848
    },
    {
      "src": "2001:470:1:18::3:1280",
      "dst": "2607:fb90:d726:7b19:5cc5:a122:d8ae:24e6",
      "destinationNameSource": "original",
      "srcPkts": 1,
      "srcBytes": 1236,
      "dstPkts": 0,
      "dstBytes": 0,
      "relativeStart": 2.741187,
      "protocolInformation": "ICMP",
      "identifier": "",
      "duration": 0.0
    },
    {
      "src": "fe80::1c91:19cd:b275:8011",
      "dst": "fe80::e7c:28ff:fef2:73aa",
      "destinationNameSource": "original",
      "srcPkts": 2,
      "srcBytes": 48,
      "dstPkts": 1,
      "dstBytes": 20,
      "relativeStart": 13.118972,
      "protocolInformation": "ICMP",
      "identifier": "",
      "duration": 4.734983
    },
    {
      "src": "fe80::e7c:28ff:fef2:73aa",
      "dst": "2607:fb90:d726:7b19:5cc5:a122:d8ae:24e6",
      "destinationNameSource": "original",
      "srcPkts": 1,
      "srcBytes": 28,
      "dstPkts": 0,
      "dstBytes": 0,
      "relativeStart": 17.853746,
      "protocolInformation": "ICMP",
      "identifier": "",
      "duration": 0.0
    }
  ]
}