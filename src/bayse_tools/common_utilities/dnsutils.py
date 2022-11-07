"""
    Copyright (c) 2022 Bayse, Inc. (maintainer: david@bayse.io)
    Date: 09/01/2022
    Code originally created by me as below.

    This file contains the DNS class, which keeps the state of all DNS data for the creation of
    well-named BayseFlows. This class has helper functions to control passive naming from the incoming
    file we're analyzing and from recently seen sessions.

    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io)

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""

import json
import pcapy
import re
import pickle
import ipaddress
from pathlib import Path
from bayse_tools.common_utilities import iputils
from bayse_tools.common_utilities import packet
from bayse_tools.common_utilities import utilities
from bayse_tools.converter import interflowutils

# some constants
A_RECORD_TYPE = 1
AAAA_RECORD_TYPE = 28
PTR_RECORD_TYPE = 12
BYTES_A_OR_AAAA_RECORDS = [b"\x00\x01\x00\x01", b"\x00\x1c\x00\x01"]  # A or AAAA record for INternet name
BYTES_NS_RECORDS = [b"\x00\x02\x00\x01"]  # NS record for INternet name
BYTES_CNAMES = b"\x00\x05\x00\x01"  # CNAME for INternet name
BYTES_PTR = b"\x00\x0c\x00\x01"  # PTR record for INternet name
BYTES_NULL = b"\x00"

class DNS:
    def __init__(self, utils):
        self.questions = dict()
        self.passive_dns_names_dict = dict()
        self.short_term_pdns_dict = dict() # saves passive DNS that was learned recently, but not necessarily during this streaming session
        self.active_dns_names = dict()
        self.unique_passive_dns_names = dict()  # results that only have one name for an IP in this file
        self.short_term_passive_dns_lock_name = "./shortTermPassiveDNS.pkl.lock"
        self.long_term_passive_dns_file_name = ""
        self.short_term_passive_dns_filename = ""
        self.dns_logfile_path = None
        if utils is None:  # shouldn't happen
            self.utils = utilities.Utilities("", "")
        else:
            self.utils = utils

    def order_passive_dns_by_timestamp(self):
        """Makes sure entries are sorted in order of timestamps
        """
        for entry in self.passive_dns_names_dict.keys():
            self.passive_dns_names_dict[entry] = sorted(self.passive_dns_names_dict[entry], key=lambda x: x[0])

    def get_unique_passive_dns_names(self):
        """Entries in this set only have one name (in this file) per IP address. This is used to update our
           long-term passive DNS file.
        """
        for entry in self.passive_dns_names_dict.keys():
            tmp_set = set()
            for tuple in self.passive_dns_names_dict[entry]:
                name = tuple[1]
                tmp_set.add(name)
            if len(tmp_set) == 1:
                self.unique_passive_dns_names[entry] = tmp_set.pop()  # grab the only name

    def get_clean_dns_names(self, name_data_raw):
        """By default, PCAPs and/or streaming data provide length counts to identify the length of the next name or
           subname of a domain. Because those are actually located in place of the expected "." characters,
           we need to replace them. This function takes the bytes associated with a name and makes sure we replace
           all weird characters with dots.
        """
        return re.sub(r"[\x00-\x2C,\x2E-\x2F,\x3A-\x40,\x5B-\x5E,\x60,\x7B-\x7F]", r".", name_data_raw)

    def parse_dns_records_from_dns_log(self):
        """Takes a Zeek dns.log, then creates and returns a dictionary of lists of tuples of packet source ports (for
           later filtering of local lookups), start times (for use later in figuring out which DNS name to use)
           and A or PTR record DNS resolutions found in the file. The resolutions are stored by name as follows:
              self.questions["someDomain.tld."]=[(someSrcPort, someTimestamp, "7.8.9.10"),(someSrcPort, someTimestamp, "1.2.3.4")]
              self.questions["4.3.2.1.in-addr.arpa."]=[(someSrcPort, someTimestamp, "someOtherDomain.tld.")]
           TODO: Handle PTR records for Zeek!

           Note that naming differences may appear (compared to PCAPs) for IPs with multiple names in a DNS log due to
           the strategy employed by Zeek (the name associated with the last DNS request before a session to the IP
           being named begins is used as the name, even if the DNS response with that name comes after the session
           begins) vs. the strategy used by Bayse (the last NAME known [i.e. from a DNS response packet] before a
           session to the IP being named begins is used as that session's name).

           Order expected (if _NOT_ JSON; "field #" lines are my annotation):
           Field #       1       2          3               4               5               6             7         8
                        ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       proto   trans_id

           Field #       9       10        11               12             13         14           15        16
                        rtt     query    qclass         qclass_name       qtype   qtype_name      rcode   rcode_name

           Field #      17      18      19      20      21        22         23        24
                        AA      TC      RD      RA      Z       answers     TTLs    rejected

           Note that all field names are not used. If you do not have a field, please give it an appropriate default
           value as defined by the Zeek format (https://docs.zeek.org/en/master/logs/dns.html).
        """
        records = []  # collect all dns records temporarily so we can parse at once
        is_json = True if self.utils.file_format is not None and "JSON" in self.utils.file_format else False
        with open(self.dns_logfile_path, "r") as dns_logfile:
            if is_json:
                flows = []
                for line in dns_logfile:
                    data = json.loads(line)
                    if type(data) == list:
                        # list of flows, so capture them all
                        flows = data
                    elif type(data) == dict:
                        flows += [data]
                    else:
                        print(f"Unrecognized JSON data {type(data)}")
                        return None
                for dns_record in flows:
                    try:
                        start_time = float(dns_record["ts"])
                        roundtrip_time = f'{dns_record["rtt"]}' if "rtt" in dns_record else "-"
                        source_port = f'{dns_record["id.orig_p"]}'
                        q_name = f'{dns_record["query"]}.'
                        q_class = f'{dns_record["qclass"]}' if "qclass" in dns_record else "-"
                        q_type = f'{dns_record["qtype"]}' if "qtype" in dns_record else "-"
                        rcode_name = f'{dns_record["rcode_name"]}' if "rcode_name" in dns_record else "NOERROR"
                        answers = ','.join(dns_record["answers"]) if "answers" in dns_record \
                                                                     and type(dns_record["answers"]) == list else "-"
                    except Exception as e:
                        print(f"Something failed while parsing Zeek JSON data. Skipping line {dns_record}:\ndue to "
                              f"likely missing field {e}")
                        continue  # something didn't parse right
                    records += [{
                        "start_time": start_time,
                        "roundtrip_time": roundtrip_time,
                        "source_port": source_port,
                        "q_name": q_name,
                        "q_class": q_class,
                        "q_type": q_type,
                        "rcode_name": rcode_name,
                        "answers": answers
                    }]
            else:
                # capture CSV format
                for line in dns_logfile:
                    if line.startswith("#"):  # ignore comment lines
                        continue
                    try:
                        dns_record = line.strip().split("\t")
                        start_time = float(dns_record[0])
                        roundtrip_time = dns_record[8]
                        source_port = dns_record[3]
                        q_name = dns_record[9] + "."  # we expect FQDNs in our files at this point
                        q_class = dns_record[10]
                        q_type = dns_record[12]
                        rcode_name = dns_record[15]
                        answers = dns_record[21]
                    except Exception as e:
                        print("Something failed while parsing Zeek plaintext log data. Skipping line:\n{}".format(e))
                        continue  # something didn't parse right
                    records += [{
                        "start_time": start_time,
                        "roundtrip_time": roundtrip_time,
                        "source_port": source_port,
                        "q_name": q_name,
                        "q_class": q_class,
                        "q_type": q_type,
                        "rcode_name": rcode_name,
                        "answers": answers
                    }]
        for record in records:
            """We only want successful DNS lookups to the Internet for A or AAAA records. However, those that seem to
               occur in a semi-broken when converting from PCAP to Zeek should also be parsed just in case. 
            """
            if ((record["q_class"] == "1" and record["q_type"] in ["1", "28"])
                or (record["roundtrip_time"] == "-" and record["rcode_name"] == "NOERROR")
               ):
                if record["q_name"] not in self.questions:
                    self.questions[record["q_name"]] = set()
                if record["answers"].find(",") != -1:  # multiple answers
                    answers_list = record["answers"].split(",")
                    for answer in answers_list:
                        try:
                            self.questions[record["q_name"]].add((record["source_port"], record["start_time"],
                                                                  str(ipaddress.ip_address(answer))))
                        except:  # it wasn't an IP address, so we'll skip collecting it
                            continue
                else:
                    try:
                        self.questions[record["q_name"]].add((record["source_port"], record["start_time"],
                                                              str(ipaddress.ip_address(record["answers"]))
                                                              )
                                                             )
                    except:  # it wasn't an IP address, so we'll skip collecting it
                        continue
            else:  # everything else should be thrown away
                continue

    def collect_dns_records_from_interflow_sample(self):
        """Takes an Interflow sample that can contain various types of records other than DNS, then creates and returns
           a dictionary of lists of tuples of packet source ports (for later filtering of local lookups), start times
           (for use later in figuring out which DNS name to use) and A or AAAA record DNS resolutions found in the file.
           The resolutions are stored by name as follows:
              self.questions["someDomain.tld."]=[(someSrcPort, someTimestamp, "7.8.9.10"),(someSrcPort, someTimestamp, "1.2.3.4")]
              self.questions["4.3.2.1.in-addr.arpa."]=[(someSrcPort, someTimestamp, "someOtherDomain.tld.")]
           TODO: Handle PTR records!
        """
        query_type_mappings = {"A": "1", "AAAA": "28"}
        is_json = True if self.utils.file_format is not None and "JSON" in self.utils.file_format else False
        with open(self.utils.original_filepath) as infile:
            if is_json:
                flows = []
                for line in infile:
                    data = json.loads(line)
                    if type(data) == list:
                        # list of flows, so capture them all
                        flows = data
                    elif type(data) == dict:
                        flows += [data]
                    else:
                        print(f"Unrecognized JSON data {type(data)}")
                        return None
            else:
                print("Expected JSON but did not get it. Quitting.")
                return None
            for flowdata in flows:
                appid_vals = interflowutils.json_extract(flowdata, "appid_name")
                if len(appid_vals) == 0 or appid_vals[0].lower() != "dns":
                    continue  # ignore everything that's not DNS here
                try:
                    ts = interflowutils.json_extract(flowdata, "timestamp")[0]
                    if len(str(ts)) == 13:
                        if "." not in str(ts):
                            start_time = float(ts) / 1000.0
                        else:
                            print("Unrecognized timestamp format. Results may be wrong.")
                            start_time = float(ts)
                    elif len(str(ts)) == 10:
                        start_time = float(ts)
                    source_port = f'{interflowutils.json_extract(flowdata, "srcport")[0]}'
                    dns_record = interflowutils.json_extract(flowdata, "metadata", dict_expected=True)[0]
                    request = dns_record["request"]
                    response = dns_record["response"]
                    q_name = f'{request["query"]}.'
                    q_class = f'{request["query_class"]}' if "query_class" in request else "-"
                    if "query_type" in request:
                        try:
                            q_type = f'{query_type_mappings[request["query_type"]]}'
                        except:
                            print(f"Skipping unhandled DNS query type {request['query_type']}")
                            q_type = "-"
                    else:
                        q_type = "-"
                    roundtrip_time = f'{response["response_time"]}' if "response_time" in response else "-"
                    rcode_name = f'{response["reply_code"]}' if "reply_code" in response else "NOERROR"
                    if "answers" in response and type(response["answers"]) == list:
                        answers = ""
                        for answer in response["answers"]:
                            if "host_type" in answer and answer["host_type"] in query_type_mappings.keys():
                                if "host_addr" in answer:
                                    answers += f"{answer['host_addr']},"
                        answers = answers[:-1] if answers.endswith(",") else answers
                    else:
                        answers = "-"
                except Exception as e:
                    print("Something failed while parsing Interflow JSON data. Skipping line:\n{}".format(e))
                    continue  # something didn't parse right

                if q_type in list(query_type_mappings.values()) or (roundtrip_time == "-" and rcode_name == "No Error"):
                    # we only want successful DNS lookups for A or AAAA records, or potentially ones without RTTs
                    if q_name not in self.questions:
                        self.questions[q_name] = set()
                    if answers.find(",") != -1:  # multiple answers
                        answers_list = answers.split(",")
                        for answer in answers_list:
                            try:
                                self.questions[q_name].add((source_port, start_time, str(ipaddress.ip_address(answer))))
                            except:  # it wasn't an IP address, so we'll skip collecting it
                                #print("Had an error with", answer)
                                continue
                    else:
                        self.questions[q_name].add((source_port, start_time, answers))
                else:  # everything else should be thrown away
                    continue

    def parse_dns_records_from_capture_file(self):
        """Takes a capture file, then creates and returns a dictionary of lists of tuples of packet source ports (for
           use in filtering later), start times (for use later in figuring out which DNS name to use) and A, AAAA,
           or PTR record DNS resolutions found in the file. The resolutions are stored by name as follows:
              self.questions["someDomain.tld."]=[(someSrcPort, someTimestamp, "7.8.9.10"),(someSrcPort, someTimestamp,
                             "1.2.3.4")]
              self.questions["4.3.2.1.in-addr.arpa."]=[(someSrcPort, someTimestamp, "someOtherDomain.tld.")]
           The parsing that occurs in this function is correlated with the DNS header, and (I believe) should
           handle both UDP and TCP DNS queries.
        """
        with pcapy.open_offline(self.utils.original_filepath) as capfile:
            capfile.setfilter("port domain")
            try:
                (hdr, pkt) = capfile.next()
            except:
                print("Got unparseable packet. Trying again")
                (hdr, pkt) = capfile.next()
            while hdr is not None:
                # we should only be getting DNS records now, so parse accordingly
                packet_info = packet.PacketInfo(pkt, hdr, self)  # prep everything for later use
                if packet_info.is_local_dns_response(pkt):
                    self.parse_local_lookup_from_packet(packet_info, pkt)
                else:
                    try:
                        hdr, pkt = capfile.next()
                    except:
                        print("Got unparseable packet. Trying again")
                        hdr, pkt = capfile.next()
                    continue
                try:
                    hdr, pkt = capfile.next()
                except:
                    print("Got unparseable packet. Trying again")
                    hdr, pkt = capfile.next()

    def parse_local_lookup_from_packet(self, packet_info, pkt, ignore_cnames=True):
        """We currently only parse DNS responses, because DNS requests don't capture the name to IP mapping that we
           need. DNS header for a response is as follows:

          |  0  1  2  3  4  5  6  7  8 |  9  10  11  12  13  14  15   |
          |  txid  flags numQs ansRR authRR  addlRR  queries(arb len) |

          In the queries portion, there are 1 or more arbitrary-length names. At the end of each of the queries
          is a null byte followed by 2 bytes for the type field followed by 2 bytes for the class field. After that the
          query information repeats again until all names (indicated by the value in the numQs field) are seen.

          The response then continues on to provide answers. Answers are constructed as follows:

          |  0  1  2  3  4  5  6  7  8 | 9  10  11  12  13  14  15 |
          | ansref type class time_to_live  datalen data(arb len)  |

          (Note that this data comes at the end of the queries section of a DNS response packet. The bytes 0-15
          identifiers above are for size/position reference only.)

          The ansref field is a 2 byte field that contains an ID associated with an answer. It's just a shorthand way
          to refer to a particular name. To figure out what string the ansref field points to, take its value (which
          will always start with binary 11 [hex 0xC, D, E, or F depending on lower bits]), ignore the top 2 bits,
          and then move that many bytes into the DNS header (starting at 0 and counting until you hit the value of
          ansref). For example, if the ansref value is 0xc016 and the DNS header data is:
          6c 54 80 00 00 01 00 00 00 0f 00 1b 09 66 65 6c 64 61 78 78 78 78 03 63 6f 6d 00 00 01 00 01 c0 16 00 02 00
          01 00 02 a3 00 00 14 01 61 0c 67 74 6c 64 2d 73 65 72
          ...then the value pointed at is 03 63 6f 6d 00 (NULL terminates the string), which is the string
          "<unprintable_character>com". There can be a number of these references to complete one name, so we make sure
          to recursively follow all of them.

          The type field is a 2 byte field that refers to what type of answer record it is (CNAME, PTR, SOA,
          etc...). The class field is a 2 byte field that refers to what class of answer record it is (such as
          0x0001, which refers to the INternet class. The time_to_live field is a 4 byte field that refers to how
          long the answer should be associated with (cached for) the question. This helps with reducing the number of
          DNS lookups any system makes. In our code, we currently ignore this field, however. The datalen field is a
          2 byte field that indicates how long the following answer data is. Finally, the data field is the actual
          answer data; its length is identified by the datalen field. For example, an IPv4 address would have a
          datalen field of 0x0004 because it is 4 bytes long, while an IPv6 address would have a datalen field of
          0x0010 (128 bytes).

          There may be other records after this, but they are not parsed in this code. Also note that we use the name
          that the client (or previous non-authoritative DNS server) asked for instead of CNAMES because we want the
          name that a user or program actually searched for, not the myriad middleboxes that float in between and
          confuse everyone's analysis. If you want to capture middlebox names instead of the real intent of the thing
          requesting a DNS name, pass "ignore_cnames=False" to this function.
        """
        txid = str(int.from_bytes(pkt[packet_info.upper_layer_start: packet_info.upper_layer_start+2], "big"))
        num_qs = int.from_bytes(pkt[packet_info.upper_layer_start+4:packet_info.upper_layer_start+6], "big")
        cnt = 0
        null_position = 0
        has_an_a_record = False
        has_aaaa_record = False
        has_ptr_record = False
        q_name = ""
        qs_section_start = packet_info.upper_layer_start + 13  # how far into a DNS packet until questions begin

        """ Deal with the queries section of the DNS response packet """
        # Every name has 4 bytes reserved for type and class info. We need to account for them when parsing each name.
        type_and_class_bytes = 4
        while cnt < num_qs:
            null_position = pkt[(qs_section_start + (type_and_class_bytes * cnt) + null_position):].find(BYTES_NULL)
            q_type = int.from_bytes(pkt[qs_section_start+null_position+1:qs_section_start+null_position+3], "big")
            if q_type == A_RECORD_TYPE:
                has_an_a_record = True
            elif q_type == AAAA_RECORD_TYPE:
                has_aaaa_record = True
            elif q_type == PTR_RECORD_TYPE:
                has_ptr_record = True
            if cnt == 0:
                # handle wonky characters in place of an expected "."
                name_data_raw = pkt[qs_section_start:qs_section_start+null_position].decode("ascii")
                q_name = self.get_clean_dns_names(name_data_raw) + "."
                if q_name not in self.questions.keys():
                    self.questions[q_name] = set()  # we don't yet have the answer
            else:
                print("Multi-question DNS responses not currently implemented. Only parsed first Q.")
                ###TODO. May not be terribly important in common usage, but should be handled at some point.
            cnt += 1

        """ Deal with the answers section of the DNS response packet """
        answers_start = qs_section_start + (type_and_class_bytes * cnt) + null_position + 1
        name_ref_size = 2  # the size of the reference for a name/answer is 2 bytes
        ttl_bytes = 4  # there are 4 bytes that describe the TTL
        ipv4_length_bytes = 4  # an IPv4 address is 4 bytes in length
        ipv6_length_bytes = 16  # an IPv6 address is 16 bytes in length
        data_length_bytes = 2  # the length of the name (in bytes) is described in 2 bytes
        nonname_fields_per_answer = name_ref_size + type_and_class_bytes + ttl_bytes + data_length_bytes
        cnames_by_qname = dict()  # collect these to ignore CNAMES when ignore_cnames is True (default)
        if ignore_cnames:
            cnames_by_qname[q_name] = set()

        # find and capture data for the appropriate records
        num_bytes_into_answers = name_ref_size
        while len(pkt) > (answers_start + num_bytes_into_answers):
            ip_addr = None
            is_cname = False
            if num_bytes_into_answers == name_ref_size:  # first time through, just ignoring the name_ref_size field
                length_to_skip = 0
            else:
                if length_to_skip == 0:
                    num_bytes_into_answers += (length_to_skip + nonname_fields_per_answer)
            data_length_start = answers_start + num_bytes_into_answers + type_and_class_bytes + ttl_bytes
            data_length_end = data_length_start + data_length_bytes
            data_length = int.from_bytes(pkt[data_length_start:data_length_end], "big")

            current_answer_start = (answers_start + num_bytes_into_answers + type_and_class_bytes + ttl_bytes +
                                    data_length_bytes)
            current_answer_end = current_answer_start + data_length
            answer_type_and_class = pkt[answers_start+num_bytes_into_answers:
                                        answers_start+num_bytes_into_answers+type_and_class_bytes]
            #print(f"Current answer begins @ byte {current_answer_start} and ends @ byte {current_answer_end}")
            try:
                data_name = None
                #print(f"Answer type and class bytes are {answer_type_and_class}")
                if ignore_cnames and answer_type_and_class == BYTES_CNAMES:
                    is_cname = True
                if (data_length in [ipv4_length_bytes, ipv6_length_bytes] and answer_type_and_class in
                        BYTES_A_OR_AAAA_RECORDS
                ):
                    """Since we're looking at an A or AAAA record, the name reference comes before the
                       answer_type_and_class bytes. So we need to walk back and grab that, which will happen by skipping 
                       the collect_dnsname_string_bytes() call below and hitting the ansref logic.
                    """
                    ip_addr = str(ipaddress.ip_address(pkt[current_answer_start:current_answer_end]))
                    #print(f"Extracted IP address {ip_addr} from current answer.")
                else:
                    #print(f"Passing bytes {pkt[data_length_start:]} to collect name string")
                    data_name = self.collect_dnsname_string_bytes(pkt[packet_info.upper_layer_start:],
                                                                  pkt[data_length_start:],
                                                                  answer_field_datalen=data_length)
                if not data_name:  # we're not looking directly at a data name
                    ansref_location = answers_start+num_bytes_into_answers-name_ref_size
                    potential_name_offset = int.from_bytes(pkt[ansref_location:ansref_location+name_ref_size], "big")
                    relevant_name = self.collect_dnsname_from_offset(pkt[packet_info.upper_layer_start:],
                                                                        potential_name_offset)
                else:
                    relevant_name = data_name
                if relevant_name:
                    relevant_name += "."  # we expect a trailing dot
                    #print(f"The string that I'm an answer for is {relevant_name}")
                    if is_cname:
                        cnames_by_qname[q_name].add(relevant_name)  # store cname mapping to q_name
                    if ip_addr:
                        if ignore_cnames:  # ignoring CNAME records only matters when we're assigning to IP addresses
                            if relevant_name in cnames_by_qname[q_name]:
                                relevant_name = q_name  # use the original query name the client asked for
                        if relevant_name not in self.questions:
                            self.questions[relevant_name] = set()
                        self.questions[relevant_name].add((packet_info.source_port, packet_info.packet_start_time,
                                                    ip_addr))
                else:
                    pass
                    #print(f"No referenced name at byte {answers_start+num_bytes_into_answers-2}")
                    # TODO: Handle cases where the name is repeated/included in the response right here.
                if has_an_a_record or has_aaaa_record:
                    if answer_type_and_class in BYTES_NS_RECORDS:
                        if relevant_name:
                            ns_bytes = pkt[current_answer_start:current_answer_end]
                            #print(f"Bytes: {ns_bytes}")
                            ns_name = self.collect_dnsname_string_bytes(pkt[packet_info.upper_layer_start:], ns_bytes)
                            if ns_name:
                                ns_name += "."  # we expect a trailing dot
                                self.questions[ns_name] = set()
                elif (has_ptr_record and pkt[answers_start+num_bytes_into_answers:
                      answers_start+num_bytes_into_answers+type_and_class_bytes] == BYTES_PTR):
                    try:
                        answer_data_raw = pkt[current_answer_start:current_answer_end].decode("ascii")
                        answer = f"{self.get_clean_dns_names(answer_data_raw)[1:]}."  # we expect a trailing dot
                        #print(f"Adding {answer} to Dict for {q_name}")
                        self.questions[q_name].add((packet_info.source_port, packet_info.packet_start_time, answer))
                    except UnicodeDecodeError as e:
                        pass
            except:
                print(f"Some non-fatal error with {str(pkt[current_answer_start:current_answer_end])} in {pkt}")
            # calc how far until the next thing we should parse
            length_to_skip = int.from_bytes(pkt[data_length_start:data_length_end], "big")
            num_bytes_into_answers += (length_to_skip + nonname_fields_per_answer)

    def collect_dnsname_string_bytes(self, dns_headerbytes, pkt_answerbytes, answer_field_datalen=None):
        """Every time we hit a string in our parsing, we need to process each label one layer at a time. Strings are
           set up as follows:
                length  string_bytes length string_bytes NULL
           The length field is a 1 byte value that identifies the length of the next piece of the string (which would be
           period-delimited, since it's a domain name). String_bytes contains the actual content of the string. All
           DNS names are ultimately NULL-terminated at the end of the string. This function accepts the raw header
           data, the DNS answer bytes, and an optional answer field length (to point out how large an upcoming
           answer will be). This combination of information allows us to determine if it's a string (which we'll
           process recursively here), if it references an offset (which we'll call our offset function to handle),
           or if it's something we completely don't handle. Each level with data should return the human-readable
           string.
        """
        name = None
        offset_name = None
        try:
            if answer_field_datalen:
                pkt_answerbytes = pkt_answerbytes[2:]  # need to chop off the 2 byte datalength length field
            name_length = pkt_answerbytes[0]
            if name_length != 0:  # it's NOT the NULL terminator
                if name_length >= 192:  # this may actually be an offset, so try to do that first!
                    # 49152 is 0xC000 (offset indicator). We should only do this when we have a referenced name to find
                    offset_raw = int.from_bytes(pkt_answerbytes[0:2], "big")
                    offset_name = self.collect_dnsname_from_offset(dns_headerbytes, offset_raw)
                if not offset_name:
                    name_data = pkt_answerbytes[1:1+name_length]
                    #print(f"Collecting {name_length} bytes of name data from {name_data}")
                    name = name_data.decode("ascii")
                    if name_data.find(BYTES_NULL) > 0:  # -1 means not found, 0 means it's an empty string
                        name = self.get_clean_dns_names(name)[1:]  # don't want the leading dot
                    else:
                        next_name = self.collect_dnsname_string_bytes(dns_headerbytes, pkt_answerbytes[name_length+1:])
                        name = f"{name}.{next_name}" if next_name else f"{name}"
                else:
                    name = f"{offset_name}"
            else:
                pass  # hit end of name data
        except:
            pass  # TODO: Handle more cases
        return name

    def collect_dnsname_from_offset(self, headerbytes, suspected_offset):
        """This allows us to recursively collect a name from a suspected offset into the DNS header."""
        name = None
        if suspected_offset & 49152 >= 49152:
            offset = (suspected_offset ^ 49152)  # remove offset indicator bits, because it's probably a real offset
            name = self.collect_dnsname_string_bytes(headerbytes, headerbytes[offset:])
        return name

    def get_passive_dns(self):
        """Takes the file we're analyzing and uses any DNS information contained in it to passively name as many
           of the external IP addresses as possible.
        """
        if self.utils.sample_type is None:
            print("Something went wrong while trying to identify sample type.")
            return None
        if self.utils.sample_type == "PCAP" and self.utils.original_filepath:  # we're dealing with PCAP data
            # collect all of the active external IP addresses that need to be identified (if possible) passively.
            iputils.collect_active_external_ips_from_capture_file(self.utils)

            # collect all of the DNS records we see in our capture file
            self.parse_dns_records_from_capture_file()
        elif self.utils.sample_type == "Zeek":  # this is Zeek data
            # collect all active external IP addresses that need to be identified
            for bayseflow in self.utils.bayseflows.keys():
                if not iputils.check_if_local_ip(str(self.utils.bayseflows[bayseflow].dest_ip)):
                    self.utils.active_external_ips.add(self.utils.bayseflows[bayseflow].dest_ip)
            # collect all DNS questions from DNS log, if it exists
            if self.dns_logfile_path is not None:
                self.parse_dns_records_from_dns_log()
        elif self.utils.sample_type == "Interflow":  # Stellar Cyber Interflow data
            for bayseflow in self.utils.bayseflows.keys():
                if not iputils.check_if_local_ip(str(self.utils.bayseflows[bayseflow].dest_ip)):
                    self.utils.active_external_ips.add(self.utils.bayseflows[bayseflow].dest_ip)
            # we've already collected DNS records earlier in this pipeline, so now we just need to use them
        elif self.utils.is_streaming:  # we're dealing with streaming data
            for bayseflow in self.utils.bayseflows.keys():
                if not iputils.check_if_local_ip(str(self.utils.bayseflows[bayseflow].dest_ip)):
                    self.utils.active_external_ips.add(self.utils.bayseflows[bayseflow].dest_ip)
        """Finally, for those IPs that are active, find the right DNS name and store it in a
           passive_dns_names_dict ordered dictionary keyed by stringified IP address with lists of tuples of resolution
           time and names as the values.
        """
        for name in self.questions.keys():
            for entry in self.questions[name]:
                dns_resolution = entry[2]
                resolution_time = entry[1]
                if dns_resolution in self.utils.active_external_ips:
                    if dns_resolution not in self.passive_dns_names_dict.keys():
                        self.passive_dns_names_dict[dns_resolution] = [(resolution_time, name[:-1])]
                    else:
                        self.passive_dns_names_dict[dns_resolution] += [(resolution_time, name[:-1])]

    def update_passive_dns_repository(self):
        """For all of the passive DNS from the current file, update the global passive DNS file if there
           are no current entries with the same IP address. If there are, delete that line from the passive DNS
           dictionary and do not save a new one.
        """

        long_term_pdns_path = Path(self.long_term_passive_dns_file_name)

        # iterate through current "ip name" for all DNS names learned passively from current file
        if not long_term_pdns_path.is_file():
            print("Warning:", long_term_pdns_path,
                  "does not exist.")
            with open(self.long_term_passive_dns_file_name, "w") as pdns_file:
                print("Created file now.")  # just create the file
        with open(self.long_term_passive_dns_file_name, "r") as infile:
            # file is lines of "IP DNSname", so store in a dict with IP as key
            long_term_pdns = dict(line.strip().split(" ") for line in infile)
        self.get_unique_passive_dns_names()

        # search the global passive DNS file for IP-to-name conflicts
        for ip in self.unique_passive_dns_names.keys():
            if ip in long_term_pdns.keys():
                if self.unique_passive_dns_names[ip] == long_term_pdns[ip]:
                    continue  # still the same name, so do nothing
                else: # replace instead of delete, because on average the newer name will be more relevant temporally (since over time, most data will be fresh)
                    #print("Found conflict with name for IP", ip + ". Replacing.")
                    long_term_pdns[ip] = self.unique_passive_dns_names[ip]
            else:  # collect a newly-learned IP-to-name mapping
                long_term_pdns[ip] = self.unique_passive_dns_names[ip]

        # store the updated passive DNS file
        with open(self.long_term_passive_dns_file_name, "w") as outfile:
            for key, value in long_term_pdns.items():
                outfile.write("%s %s\n" % (key, value))

    def map_destination_ips_to_names(self):
        """Rewrite destination IPs (i.e. the thing on the Internet, generally) with names whenever possible.
           The strategy for doing this as correctly as possible is as follows:
                0. If we already have naming information in a flow/session (such as in Interflow), use it.
                1. Replace any destination IPs that used passive DNS for the EXACT session (by time) from current
                   file.
                2. (streaming-specific) If a short-term passive DNS file exists, see if there is information in there
                   for the EXACT session (by time) we're currently trying to label. If so, label it.
                3. Replace any destination IPs with the most recent name we have from the current file (so if some IP
                   has multiple names for it in this file, we use the one that was most recently resolved at the time
                   we see this session.
                4. (streaming-specific) If a short-term passive DNS file exists, replace any destination IPs with the
                   most recent name we have. (NOTE: entries expire after ~5 minutes)
                5. Replace any destination IPs that are still unnamed using our long-term passive DNS collection,
                   which only stores names for IPs that we've never seen have more than one name.
                6. Replace any remaining destination IPs with what we learn from an active reverse DNS lookup.
                7. All remaining destination IPs stay as IP addresses that we attempt to lookup server-side.
        """

        self.long_term_passive_dns_file_name = "./longTermPassiveDNS.txt"
        try:
            long_term_pdns_file = Path(self.long_term_passive_dns_file_name)
        except:
            print("Warning:", long_term_pdns_file,
                              "does not exist. Will not use long-term passive DNS for this file.")
        long_term_pdns_dict = dict()
        self.short_term_passive_dns_filename = "./shortTermPassiveDNS.pkl"
        try:
            short_term_pdns_file = Path(self.short_term_passive_dns_filename)
            # the above we don't actually use when we're not streaming, but it's easier to instantiate the file and
            # ignore it than to rewrite the logic a little farther down.
            if self.utils.is_streaming: # only do this for streaming logic
                with open(short_term_pdns_file, "rb") as stpdf:
                    self.short_term_pdns_dict = pickle.load(stpdf)
                # merge short_term_pdns_file into the passive dns names dict so it can be sorted below:
                # get an iterator for this dict so we can pull its changes into the current passive dns names dict
                for entry in self.short_term_pdns_dict.keys():
                    if entry in self.passive_dns_names_dict.keys():
                        for val in self.short_term_pdns_dict[entry]:
                            if val not in self.passive_dns_names_dict[entry]:
                                self.passive_dns_names_dict[entry] += [val]
                    else:
                        self.passive_dns_names_dict[entry] = self.short_term_pdns_dict[entry]
        except:
            if self.utils.is_streaming:  # only do this for streaming logic
                print("Short-term passive DNS file", short_term_pdns_file
                    , "does not exist (or some other error). Will not use short-term knowledge for this iteration.")

        self.order_passive_dns_by_timestamp()  # make sure we're sorted by timestamp

        if not long_term_pdns_file.is_file():
            print("Warning:", long_term_pdns_file,
                  "does not exist. Will not use long-term passive DNS for this file.")
        else:
            with open(self.long_term_passive_dns_file_name) as infile:
                # file is lines of "IP DNSname", so store in a dict with IP as key
                long_term_pdns_dict = dict(line.strip().split(" ") for line in infile)

        entry = None  # entry is only used for streaming logic
        with open(short_term_pdns_file, "wb") as stpdf_handle: # overwrite it every time to keep updates sanely
            for bayseflow in self.utils.bayseflows.keys():
                named = False  # keep track of whether we've named something each time
                if self.utils.bayseflows[bayseflow].dest_name != "":  # we already have naming from the session itself
                    self.utils.bayseflows[bayseflow].destination_name_source = "session"
                    named = True
                    continue
                flow_ip = self.utils.bayseflows[bayseflow].dest_ip  # local var to make things less verbose in this loop
                if flow_ip in self.passive_dns_names_dict.keys():
                    try:
                        for tuple in list(reversed(self.passive_dns_names_dict[flow_ip])):
                            """The list of tuples is already reverse ordered by timestamp so the first time that is less
                            is the most correct one to use here. """
                            resolution_timestamp = tuple[0]  # grab timestamp
                            name = tuple[1]
                            if resolution_timestamp <= self.utils.bayseflows[bayseflow].absolute_start_time:
                                self.utils.bayseflows[bayseflow].dest_name = name
                                self.utils.bayseflows[bayseflow].destination_name_source = "passive"
                                named = True
                                entry = (resolution_timestamp, name)
                                break  # quit as soon as we get one
                            else:
                                continue
                    except:
                        print("Error: IP address", flow_ip, "has run out of passive_dns_names_dict.")
                        continue
                if not named and self.utils.bayseflows[bayseflow].dest_ip in long_term_pdns_dict.keys():
                    # replace any possible destinations with passive DNS from overall PDNS file, if it exists.
                    self.utils.bayseflows[bayseflow].dest_name = long_term_pdns_dict[flow_ip]
                    self.utils.bayseflows[bayseflow].destination_name_source = "cache"
                    named = True
                if not named:
                    try:  # if there is something in our current file, grab first one.
                        #print("Deciding to label", flow_ip, "with", self.passive_dns_names_dict[flow_ip][0][1])
                        self.utils.bayseflows[bayseflow].dest_name = self.passive_dns_names_dict[flow_ip][0][1]
                        self.utils.bayseflows[bayseflow].destination_name_source = "passive"
                        entry = (self.passive_dns_names_dict[flow_ip][0][0], self.passive_dns_names_dict[flow_ip][0][1])
                        named = True
                    except:  # if not, just keep the IP
                        self.utils.bayseflows[bayseflow].dest_name = flow_ip
                        self.utils.bayseflows[bayseflow].destination_name_source = "original"
                if self.utils.is_streaming: # only do this for streaming logic
                    if named and entry is not None:  # we had picked up our name from current file's passive DNS
                        # capture the particular entry in the short-term passive DNS file
                        if flow_ip not in self.short_term_pdns_dict.keys():
                            """If a name doesn't exist in the current version of the short-term dns names dict, we should
                               save it so we can write it to the file.
                            """
                            self.short_term_pdns_dict[flow_ip] = [(entry[0], entry[1])]
                        else:
                            """If a name DOES exist in the current version of the short-term dns names dict (but it doesn't
                               contain the exact timestamp we currently have), we should UPDATE it so we can write it to
                               the file.
                            """
                            if (entry[0], entry[1]) not in self.short_term_pdns_dict[flow_ip]:
                                self.short_term_pdns_dict[flow_ip] += [(entry[0], entry[1])]
                continue
            if self.utils.is_streaming: # only do this for streaming logic
                pickle.dump(self.short_term_pdns_dict, stpdf_handle) # at the end, (over)write pickle file with our current knowledge

    def collect_local_lookups(self):
        """Not currently used. This function parses the questions dictionary and collects the destination ports and
           timestamps for all of the lookups that are either local forward lookups for IPv4:
               questions["hello.local."]=[("44332", "1234.5678", "10.17.18.24")]
           or local reverse lookups:
               questions["5.15.168.192.in-addr.arpa."]=[("55117", "2345.6789", "hi.local.")]
           These are collected in a list and returned to the caller.

           Some testing examples for local forward and local reverse lookups:
           questions["hello.local."]=[("51317", "1234.5678", "10.17.18.24"),("54217", "1235.7789", "172.16.18.40")]
           questions["5.15.168.192.in-addr.arpa."]=[("8675", "1245.5432", "hi.local.")]
        """
        local_lookups = []
        names = self.questions.keys()
        for name in names:
            if len(self.questions[name]) == 0:
                continue
            for entry in self.questions[name]:  # iterate through all resolutions for a given DNS name
                dest_port = entry[0]
                resolution = entry[2]
                # remove local forward lookups -- TODO: need to correctly handle IPv6
                if re.match(self.utils.local_ips_forward_regex, resolution):
                    local_lookups += [dest_port + " or "]
                # remove local reverse lookups -- TODO: need to correctly handle IPv6
                else:
                    if re.match(self.utils.local_ips_reverse_regex, name):
                        local_lookups += [dest_port + " or "]
        # remove extra " or " from end of list
        if len(local_lookups) > 0:
            last = local_lookups.pop()
            local_lookups += [last[:-4]]
        return local_lookups
