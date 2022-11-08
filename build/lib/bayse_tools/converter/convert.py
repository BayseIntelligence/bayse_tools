"""
    Copyright (c) 2022 Bayse, Inc. (maintainer: david@bayse.io)
    Date: 09/01/2022
    Code originally created by me as below.

    The functions in this file handle PCAP, PCPANG, Zeek, and Interflow files. They convert all traffic into BayseFlow
    format (which is similar to but more lightweight than Zeek flows).

    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io)

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""

import argparse
import os
import subprocess
import sys
import platform
import pathlib
import time

from bayse_tools.converter import pcaputils
from bayse_tools.converter import generic_flowutils
from bayse_tools.converter import zeekutils
from bayse_tools.converter import interflowutils
from bayse_tools.common_utilities import utilities
from bayse_tools.common_utilities import dnsutils


def finish_conversion(dnshelper, utils, should_label=False, api_key=None, env_var=None, labeling_path=None,
                      converter_start=None):
    """Handle final conversion of inputs that don't depend on input-specific information. Default to believing that the
       initial pieces of the pipeline were successful unless we are told otherwise by incoming knowledge. Doing so
       allows us to create a valid file with no data when there are either no flows or something has failed. If the
       caller requests to label the BayseFlow file, we attempt to do so.
    """
    if len(utils.bayseflows) > 0:
        # get passive DNS
        dnshelper.get_passive_dns()

        # use domain names instead of IP addresses wherever possible
        dnshelper.map_destination_ips_to_names()

        # add current file's DNS to the PDNS file (for PCAPs).
        dnshelper.update_passive_dns_repository()
    else:
        print("No BayseFlows created from input source.")

    # save BayseFlows to file for hashing and to prepare final format
    utils.save_bayseflows_to_file()
    uuid = utils.get_random_uuid()
    utils.set_hash_value_for_sample(uuid)

    # capture BayseFlows in JSON format, and store with all information for final transmission
    utils.prepare_final_output_file()

    # check if output file looks sane
    utils.check_output_sanity()

    print("Cleaning up temporary files")
    utils.cleanup_files()

    if utils.output_dir is not None:
        # relocate the file
        utils.output_dir = pathlib.Path(utils.output_dir)  # make sure it's a real Path object
        # create the directory if it doesn't exist
        utils.output_dir.mkdir(parents=True, exist_ok=True)
        start_path = pathlib.Path(utils.bayseflow_output_filepath)
        filename = start_path.stem + start_path.suffix
        utils.bayseflow_output_filepath = str(start_path.rename(pathlib.PurePath(utils.output_dir, filename)))
    if converter_start:
        converter_end = time.perf_counter()
        total_time = converter_end - converter_start
        total_flows = len(utils.bayseflows) if len(utils.bayseflows) > 0 else 1
        print(f"Conversion completed in {total_time:0.1f}s at rate of {total_flows/total_time} BayseFlows/s")
    if should_label:
        if converter_start:
            labeling_start = time.perf_counter()
        else:
            labeling_start = None
        print("Adding labeling information to BayseFlow file.")
        api_key = api_key if api_key else os.environ.get(env_var)
        # construct the path to the labeling executable
        labeling_binary = f"{labeling_path}/" \
                          f"{utils.labeling_binary_name}" if labeling_path else utils.labeling_binary_name
        result = subprocess.run([labeling_binary, "-k", api_key, "--files", utils.bayseflow_output_filepath],
                                capture_output=True, text=True)
        if result.stdout:
            print(f"Details: {result.stdout}")
        if result.stderr:
            print(result.stderr)
            print("Labeling unsuccessful")
        if labeling_start:
            labeling_end = time.perf_counter()
            total_time = labeling_end - labeling_start
            print(f"Labeling completed in {labeling_end - labeling_start:0.1f}s at rate of {total_flows/total_time} "
                  f"BayseFlows/s")
    print("Conversion complete! Final BayseFlow Output stored at", utils.bayseflow_output_filepath)


def convert_zeek(zeekfile_location, zeek_dnsfile_location=None, output_dir=None, should_label=False, api_key=None,
                 env_var=None, labeling_path=None, converter_start=None):
    """Handles all of the Zeek-specific conversion needs. Takes an optional DNS log.
    """
    my_platform = platform.system().lower()
    utils = utilities.Utilities(str(zeekfile_location), my_platform, output_dir=output_dir, sample_type="Zeek")
    dnshelper = dnsutils.DNS(utils)  # create an instance of the DNS class to use

    if zeek_dnsfile_location is not None:
        # store it if it exists
        dnshelper.dns_logfile_path = str(zeek_dnsfile_location)

    # there's no filtered file in Zeek, so just grab name from original file.
    utils.filtered_filepath = utils.original_filepath

    # make sure the file is a valid Zeek conn log
    generic_flowutils.validate_file_format(utils)

    # most of the heavy lifting happens here
    zeekutils.zeek_2_bayseflows(utils)
    finish_conversion(dnshelper, utils, should_label, api_key, env_var, labeling_path, converter_start)


def convert_interflow(interflow_location, output_dir=None, should_label=False, api_key=None, env_var=None,
                      labeling_path=None, converter_start=None):
    """Handles all of the Interflow-specific conversion needs.
    """
    my_platform = platform.system().lower()
    utils = utilities.Utilities(str(interflow_location), my_platform, output_dir=output_dir, sample_type="Interflow")
    dnshelper = dnsutils.DNS(utils)  # create an instance of the DNS class to use

    # there's no filtered file in Interflow, so just grab name from original file.
    utils.filtered_filepath = utils.original_filepath

    # make sure the file is a valid Interflow log
    generic_flowutils.validate_file_format(utils)

    # most of the heavy lifting happens here
    interflowutils.interflow_2_bayseflows(utils, dnshelper)
    finish_conversion(dnshelper, utils, should_label, api_key, env_var, labeling_path, converter_start)


def convert_pcap(pcapfile_location, output_dir=None, should_label=False, api_key=None, env_var=None,
                 labeling_path=None, converter_start=None):
    """Handles all of the PCAP-specific conversion needs. Supports PCAPNG as well.
    """
    my_platform = platform.system().lower()
    utils = utilities.Utilities(str(pcapfile_location), my_platform, output_dir=output_dir, sample_type="PCAP")
    dnshelper = dnsutils.DNS(utils)  # create an instance of the DNS class to use

    # make sure the file is a valid capture file
    pcaputils.validate_file_format(utils)

    # most of the heavy lifting happens here
    pcaputils.pcap_to_bayseflow_converter(utils, dnshelper)

    """We only know how long a BayseFlow lasted when we've captured it all, so go back through the dictionary and 
       update this now.
    """
    utils.set_bayseflow_durations()
    utils.set_stream_ids_for_pcap()
    finish_conversion(dnshelper, utils, should_label, api_key, env_var, labeling_path, converter_start)


if __name__ == "__main__":
    # handle all arguments
    parser = argparse.ArgumentParser()
    zeek_group = parser.add_argument_group("zeek", "arguments available when analyzing Zeek files")
    zeek_group.add_argument("-z", "--zeekConnLog", help="a valid Zeek conn.log file", type=str)
    zeek_group.add_argument("-d", "--zeekDNSLog", help="a valid Zeek dns.log file")

    cap_group = parser.add_argument_group("pcap", "arguments available when analyzing capture (CAP, PCAP, PCAPNG) files")
    cap_group.add_argument("-p", "--pcap",
                          help="indicates that a capture file (usually PCAP or PCAPNG) will be the input file to parse",
                          type=str
                           )

    interflow_group = parser.add_argument_group("interflow", "arguments available when analyzing Interflow files")
    interflow_group.add_argument("--interflowLog", help="a valid Interflow JSON log file", type=str)

    labeling_group = parser.add_argument_group("labeling", "arguments for handling labeling")
    labeling_group.add_argument("-l", "--label",
                              help="add labels to the BayseFlow file",
                              action="store_true")
    labeling_group.add_argument("--labelingPath", help="the location of the labeling binary", type=str)
    labeling_group.add_argument("-k", "--apiKey", help="the API key to use for labeling", type=str)
    labeling_group.add_argument("-e", "--environmentVariable",
                              help="name of the environment variable where your API key is stored",
                              type=str)
    stats_group = parser.add_argument_group("stats", "arguments to use for collecting statistics about the conversion.")
    stats_group.add_argument("-t", "--timing", help="capture diagnostics about timing of each step",
                             action="store_true")
    args = parser.parse_args()

    pcapfile_location = None
    zeekfile_location = None
    zeek_dnsfile_location = None
    interflow_location = None

    if (args.zeekConnLog and args.pcap) or (args.pcap and args.interflowLog) or (args.zeekConnLog and args.interflowLog):
        """
        Check if multiple input types were inputted 
        """
        print("Error: can only parse Zeek OR PCAP OR Interflow, not many at same time.")
        sys.exit(1)
    elif args.zeekConnLog:
        zeekfile_location = pathlib.Path(args.zeekConnLog)
        if not zeekfile_location.is_file():
            print("Error:", zeekfile_location, "does not exist.")
            sys.exit(1)
        if args.zeekDNSLog:
            zeek_dnsfile_location = pathlib.Path(args.zeekDNSLog)
            if not zeek_dnsfile_location.is_file():
                print("Error:", zeek_dnsfile_location, "does not exist.")
                sys.exit(1)
        else:
            print("No Zeek DnsService log specified. Naming of BayseFlows may be suboptimal.")
            zeek_dnsfile_location = None
    elif args.pcap:
        pcapfile_location = pathlib.Path(args.pcap)
        if not pcapfile_location.is_file():
            print("Error:", pcapfile_location, "does not exist.")
            sys.exit(1)
    elif args.interflowLog:
        interflow_location = pathlib.Path(args.interflowLog)
    else:
        print("Missing -p, -z, or --interflowLog argument.")
        sys.exit(1)

    # if we want to label the output, capture relevant args
    api_key = None
    environment_variable = None
    label = False
    labeling_binary_path = None
    if args.label:
        label = True
        if not args.apiKey and not args.environmentVariable:
            print(f"Missing API key information for labeling. Labeling will fail.")
        else:
            api_key = args.apiKey if args.apiKey else None
            environment_variable = args.environmentVariable if args.environmentVariable else None
        if not args.labelingPath:
            print(f"Missing path to labeling binary. Labeling may fail unless it is in your PATH variable.")
        else:
            labeling_binary_path = args.labelingPath

    """
        Input type-specific file processing in this section
    """
    if args.timing:
        converter_start = time.perf_counter()
    else:
        converter_start = None
    if args.zeekConnLog:
        convert_zeek(zeekfile_location,
                     zeek_dnsfile_location,
                     should_label=label,
                     api_key=api_key,
                     env_var=environment_variable,
                     labeling_path=labeling_binary_path,
                     converter_start=converter_start
                     )
    elif args.pcap:
        convert_pcap(pcapfile_location, should_label=label, api_key=api_key, env_var=environment_variable,
                     labeling_path=labeling_binary_path, converter_start=converter_start)
    elif args.interflowLog:
        convert_interflow(interflow_location, should_label=label, api_key=api_key, env_var=environment_variable,
                          labeling_path=labeling_binary_path, converter_start=converter_start)
