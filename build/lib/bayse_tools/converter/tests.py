"""
    Copyright (c) 2022 Bayse, Inc. (maintainer: david@bayse.io)
    Date: 09/01/2022
    Code originally created by me as below.

    This file contains tests for the converter code.

    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io)

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""

import copy
import json
import pathlib
import importlib.resources
from bayse_tools.converter import convert


def run_tests():
    test_cases = [
                    {"inputType": "pcapng"
                        , "filename": "testCase1_chromeWin10StartChromeBrowser.pcapng"
                     }
                    ,
                    {"inputType": "pcapng"
                        , "filename": "testCase2_chromeWin10VisitAmazonScamaDotCom.pcapng"
                     }
                    ,
                    {"inputType": "pcapng"
                        , "filename": "testCase3_oneLocalPacketIsProcessable.pcapng"
                     }
                    ,
                    {"inputType": "pcapng"
                        , "filename": "testCase4_oneNonLocalPacketIsProcessable.pcapng"
                     }
                    ,
                    {"inputType": "pcapng"
                        , "filename": "testCase5_oneFlowPlusLocalDNSIsProcessable.pcapng"
                     }
                    ,
                    {"inputType": "pcap"
                        , "filename": "testCase6_icmp_plus_others.pcap"
                     }
                    ,
                    {"inputType": "zeek"
                         , "filename": "testCase7_chromeWin10StartChromeBrowser.conn.log"
                         , "hasDNS": True
                     }
                    ,
                    {"inputType": "zeek"
                         , "filename": "testCase8_chromeWin10VisitAmazonScamaDotCom.conn.log"
                         , "hasDNS": True
                     }
                    ,
                    {"inputType": "zeek"
                         , "filename": "testCase9_oneLocalFlowIsProcessable.conn.log"
                         , "hasDNS": False
                     }
                    ,
                    {"inputType": "zeek"
                         , "filename": "testCase10_oneNonLocalFlowIsProcessable.conn.log"
                         , "hasDNS": False
                     }
                    ,
                    {"inputType": "zeek"
                         , "filename": "testCase11_emptySansHeaders.conn.log"
                         , "hasDNS": False
                     }
                    ,
                    {"inputType": "zeek"
                        , "filename": "testCase12_icmp_plus_others.conn.log"
                     , "hasDNS": True
                     }
                    ,
                    {"inputType": "pcap"
                        , "filename": "testCase13_mtbDotcom_bangInPlaceOfDot.pcap"
                     }
                    ,
                    {"inputType": "pcap"
                        , "filename": "testCase14_faturasatacada_phish_with_nonephemeral_dport9999.pcap"
                     }
                    ,
                    {"inputType": "zeek"
                        , "filename": "testCase15_chromeWin10StartChromeBrowser_JSON.conn.log"
                        , "hasDNS": True
                     }
                    ,
                    {"inputType": "zeek"
                        , "filename": "testCase16_chromeWin10VisitAmazonScamaDotCom_JSON.conn.log"
                        , "hasDNS": True
                     }
                    ,
                    {"inputType": "zeek"
                        , "filename": "testCase17_oneLocalFlowIsProcessable_JSON.conn.log"
                        , "hasDNS": False
                     }
                    ,
                    {"inputType": "zeek"
                        , "filename": "testCase18_oneNonLocalFlowIsProcessable_JSON.conn.log"
                        , "hasDNS": False
                     }
                    ,
                    {"inputType": "zeek"
                        , "filename": "testCase19_icmp_plus_others_JSON.conn.log"
                        , "hasDNS": True
                     }
                    ,
                    {"inputType": "zeek"
                        , "filename": "testCase20_oneNonLocalFlowIsProcessable_newstyle_JSON.conn.log"
                        , "hasDNS": False
                     }
                    ,
                    {"inputType": "zeek"
                        , "filename": "testCase21_icmp_plus_others_newstyle_JSON.conn.log"
                        , "hasDNS": True
                     }
                    ,
                    {"inputType": "interflow"
                        , "filename": "testCase22_oneInterflowPlusDNS.if"
                     }
                    ,
                    {"inputType": "pcap"
                        , "filename": "testCase23_ipv6_withDNS_and_icmpv6.pcap"
                     }
                    ,
                    {"inputType": "zeek"
                        , "filename": "testCase24_ipv6_withDNS_and_icmpv6.conn.log"
                        , "hasDNS": True
                     }
                    ,
                    {"inputType": "pcap"
                        , "filename": "testCase25_icmpTunneling.pcap"
                     }
                    ,
                    {"inputType": "zeek"
                        , "filename": "testCase26_icmpTunneling.conn.log"
                        , "hasDNS": True
                     }
                    ,
                    {"inputType": "pcap"
                        , "filename": "testCase27_internetScanning.pcap"
                     }
                    ,
                    {"inputType": "pcap"
                        , "filename": "testCase28_testForNegativeBytecountsSource.pcap"
                     }
                    ,
                    {"inputType": "pcap"
                        , "filename": "testCase29_testForNegativeBytecountsDestination.pcap"
                     },
                    {"inputType": "pcap"
                        , "filename": "testCase30_dnsNotButchered.pcapng"
                     }
                    ,
                    {"inputType": "pcap"
                        , "filename": "testCase31_dnsNotWronglyAttributed.pcap"
                     }
                    ,
                    {"inputType": "pcap"
                        , "filename": "testCase32_gre_encapsulation.cap"
                     }
                    ,
                    {"inputType": "pcap"
                        , "filename": "testCase33_ipip_encapsulation.cap"
                     }
                ]
    test_dir = None
    with importlib.resources.files(__package__).joinpath("tests") as p:
        test_dir = p
    inputs_location = str(pathlib.PurePath(test_dir, "inputs"))
    outputs_location = pathlib.PurePath(test_dir, "outputs")
    expected_outputs_location = pathlib.PurePath(test_dir, "expectedOutputs")
    bayse_format = "BayseFlow"
    for test in test_cases:
        try:
            if test["inputType"] in ["pcap", "pcapng"]:
                print(f"Converting {test['filename']} from {test['inputType'].upper()} to {bayse_format}.")
                convert.convert_pcap(f"{inputs_location}/{test['filename']}",
                                     output_dir=outputs_location
                                     )
            elif test["inputType"] == "zeek":
                print(f"Converting {test['filename']} from {test['inputType'].upper()} to {bayse_format}.")
                if "hasDNS" in test.keys() and test["hasDNS"]:
                    dns_name = test["filename"].replace(".conn.log", ".dns.log")
                    convert.convert_zeek(f"{inputs_location}/{test['filename']}",
                                         zeek_dnsfile_location=f"{inputs_location}/{dns_name}",
                                         output_dir=outputs_location
                                         )
                else:
                    convert.convert_zeek(f"{inputs_location}/{test['filename']}",
                                         output_dir=outputs_location
                                         )
            elif test["inputType"] == "interflow":
                print(f"Converting {test['filename']} from {test['inputType'].upper()} to {bayse_format}.")
                convert.convert_interflow(f"{inputs_location}/{test['filename']}",
                                          output_dir=outputs_location
                                          )
            else:
                print(f"Unrecognized input type {test['inputType']}...skipping!")
                continue
            print("===============================================================")
        except:
            print("Something unexpected happened for this test case. Skipping.")
    print(f"Tests generation complete! Comparing BayseFlows of tests in {outputs_location} to those in "
          f"{expected_outputs_location} to determine if any issues have occurred."
          )
    diffs = 0
    name_diffs = 0
    for tc in test_cases:
        name = tc["filename"]
        p = pathlib.Path(name)
        if p.suffix in [".log", ".if"]:
            updated_name = str(p.with_suffix(".bf"))
        else:
            updated_name = p.stem + "_filtered.bf"
        print(f"Comparing expected vs. output for {updated_name}")
        expected_loc = pathlib.PurePath(expected_outputs_location, updated_name)
        output_loc = pathlib.PurePath(outputs_location, updated_name)
        expected_data = None
        output_data = None
        try:
            with open(expected_loc, "rb") as expected:
                expected_data = json.load(expected)
            with open(output_loc, "rb") as output:
                output_data = json.load(output)
        except:
            print("Something went wrong while trying to load files. Skipping test. Review above logs for details.")
            continue
        if expected_data is None or output_data is None:
            print("Something went wrong while trying to load files. Skipping test. Review above logs for details.")
            continue

        if expected_data["trafficDate"] != output_data["trafficDate"]:
            print(f"Traffic dates differ: Expected {expected_data['trafficDate']} vs. Output "
                  f"{output_data['trafficDate']}"
                  )
        ordered_expected = []
        for bayseflow in expected_data["BayseFlows"]:
            ordered_expected += [set(bayseflow.items())]
        ordered_output = []
        for bayseflow in output_data["BayseFlows"]:
            ordered_output += [set(bayseflow.items())]
        ordered_expected_length = len(ordered_expected)
        ordered_output_length = len(ordered_output)
        if ordered_expected_length != ordered_output_length:
            print(f"Different number of BayseFlows: Expected {ordered_expected_length} output vs. Output "
                  f"{ordered_output_length}"
                  )
            diffs += abs(ordered_expected_length - ordered_output_length)
        for i in range(0, ordered_expected_length):
            try:
                if ordered_output_length > i and len(ordered_expected[i] ^ ordered_output[i]) != 0:
                    # remove fields affected by DNS to see if it may be a cache difference or a DNS problem
                    oe_flow = copy.deepcopy(list(ordered_expected[i]))
                    oo_flow = copy.deepcopy(list(ordered_output[i]))
                    naming_fields = ["dst", "destinationNameSource"]
                    oe_name_data = []
                    oo_name_data = []
                    for field in ordered_expected[i]:
                        if field[0] in naming_fields:
                            oe_name_data += [field]
                            oe_flow.remove(field)
                    for field in ordered_output[i]:
                        if field[0] in naming_fields:
                            oo_name_data += [field]
                            oo_flow.remove(field)
                    differing = []
                    for remaining_field in oe_flow:
                        if remaining_field not in oo_flow:
                            differing += [remaining_field]
                    if differing:
                        print(f"Non-Naming Mismatch for BayseFlow {i}:\nExpected {ordered_expected[i]} \nvs.\n"
                              f"Received {ordered_output[i]}"
                              )
                    else:
                        print(f"Naming-related Mismatch for BayseFlow {i}:\nExpected {oe_name_data}\n"
                              f"Received {oo_name_data}\nIf this occurs for a few flows it's likely transient and due "
                              f"to differences in caches, but if it is happening for all flows (or if any of the "
                              f"mismatches occurs on a 'passive' or 'session' destinationNameSource) it is likely a "
                              f"dnsutils problem."
                              )
                        name_diffs += 1
                    diffs += 1
            except Exception as e:
                print(f"Error: {e}")
                diffs += 1
                break
    if diffs == 0:
        print("Success! No differences between expected and output!")
    else:
        print(f"Found {diffs} differences (of which {name_diffs} are DNS naming differences) between expected and "
              f"output data. Please review."
              )

