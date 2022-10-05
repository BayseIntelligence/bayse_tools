"""
    Copyright (c) 2022 Bayse, Inc. (maintainer: david@bayse.io)
    Date: 09/01/2022
    Code originally created by me as below.

    This file contains all of the main pieces needed to successfully stream and label BayseFlows from a local system.

    Copyright 2021-2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io)

    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""

import argparse
import sys
import pickle
import sched
import threading
import time
import os
import platform
from pathlib import Path
from filelock import SoftFileLock, Timeout
from bayse_tools.common_utilities import captureutils
from bayse_tools.common_utilities import utilities


def schedule_cleanup(**kwargs):
    s = sched.scheduler(time.time, time.sleep)
    interval = kwargs['interval']

    def clean_up_short_term_passive_dns(scheduler):
        """The short-term passive DNS file is meant to keep track of DNS resolutions that may've happened recently,
            but that did not happen during a current streaming capture's time period. These entries should be expired
            regularly so as to not be over-zealous with labeling sessions. Since we have the long-term passive DNS file
            to capture DNS resolutions that don't change frequently, a good default time period to expire entries is
            five minutes (which is a commonly-used timeout for many popular sites).
        """
        short_term_passive_dns_filename = "./shortTermPassiveDNS.pkl"
        short_term_passive_dns_lock_name = "./shortTermPassiveDNS.pkl.lock"
        now = time.time()
        try:
            short_term_pdns_file = Path(short_term_passive_dns_filename)
            lock = SoftFileLock(short_term_passive_dns_lock_name)
            try:
                with lock.acquire(timeout=10):
                    cleaned_up_dict = dict()
                    with open(short_term_pdns_file, "rb") as stpdf:
                        short_term_pdns_dict = pickle.load(stpdf)
                        for entry in short_term_pdns_dict.keys():
                            for record in short_term_pdns_dict[entry]:
                                ts = record[0]
                            # use list comprehension to only keep those that aren't stale
                            cleaned_up_dict[entry] = [record for record in short_term_pdns_dict[entry] if (now - record[0] < 300)]
                            if len(cleaned_up_dict[entry]) == 0:
                                cleaned_up_dict.popitem()
                    with open(short_term_pdns_file, "wb") as stpdf:
                        pickle.dump(cleaned_up_dict, stpdf)
            except Timeout:
                print("Lock acquisition for cleaning up short-term passive DNS took too long. Something might be wrong.")
        except:
            pass  # something went wrong, which may just be that there's no short term passive dns file
        s.enter(interval, 1, clean_up_short_term_passive_dns, (scheduler,))
    s.enter(interval, 1, clean_up_short_term_passive_dns, (s,))
    s.run()


def start(interface, duration=60, is_verbose=False, should_label=False, api_key=None, env_var=None, labeling_path=None):
    """Start the streaming functionality. Expects the name of the interface to capture network data from, and a duration
        (in seconds) to capture before creating a BayseFlow file. This function will run until killed, continually
        generating BayseFlow files. If no API key is available and labeling is requested, no BayseFlows will be
        successfully  labeled.
    """
    my_platform = platform.system().lower()
    if my_platform in ["linux", "darwin"]:
        os.nice(20)  # Linux-specific, values are [-20,20] (higher being "nicer" to other processes)
    else:
        print("Need to implement resource limiting on Windows and other non-Linux systems (if it's too resource-intensive)!")
    cleanup_thread = threading.Thread(target=schedule_cleanup, kwargs={"interval": 60})  # clean up every minute
    cleanup_thread.start()

    start_time = time.time()
    while True:
        # set up threading for capturing and processing
        utils = utilities.Utilities(None, my_platform, sample_type="PCAP")  # create an instance of utils to use
        capture_thread = threading.Thread(target=captureutils.capture,
                                          kwargs={"interface": interface,
                                                  "bpf": captureutils.create_bpf(),
                                                  "utils": utils,
                                                  "is_verbose": is_verbose,
                                                  }
                                          )
        processing_thread = threading.Thread(target=captureutils.process_packets,
                                              kwargs={"utils": utils,
                                                      "is_verbose": is_verbose
                                                      }
                                             )
        saving_timer = threading.Timer(duration,
                                        captureutils.save_bayseflows,
                                        kwargs={"utils": utils,
                                                "capture_thread": capture_thread,
                                                "processing_thread": processing_thread,
                                                "key": api_key,
                                                "environment_variable": env_var,
                                                "should_label": should_label,
                                                "labeling_path": labeling_path,
                                                "is_verbose": is_verbose
                                                }
                                        )
        print(f"Capturing on {interface} for {str(duration)} seconds")

        # Start processing the packets we're collecting in our utilities packet buffer
        saving_timer.start()
        capture_thread.start()
        processing_thread.start()
        time.sleep(duration - ((time.time() - start_time) % duration))


if __name__ == "__main__":

    # handle all arguments
    parser = argparse.ArgumentParser()
    streaming_group = parser.add_argument_group("Streaming Arguments", "arguments available when configuring streaming")
    streaming_group.add_argument("-i", "--interface", help="the name of the interface to capture network data from",
                                 type=str
                                 )
    streaming_group.add_argument("-d", "--duration", help="(optional) how long (in seconds) to capture before creating "
                                                          "a new sample (default is 60 seconds)", type=int)

    labeling_group = parser.add_argument_group("labeling", "arguments for handling labeling")
    labeling_group.add_argument("-l", "--label",
                                help="add labels to the BayseFlow file",
                                action="store_true")
    labeling_group.add_argument("--labelingPath", help="the location of the labeling binary", type=str)
    labeling_group.add_argument("-k", "--apiKey", help="the API key to use for labeling", type=str)
    labeling_group.add_argument("-e", "--environmentVariable",
                                help="name of the environment variable where your API key is stored",
                                type=str)
    args = parser.parse_args()
    if not args.interface:
        print("Error: Must specify an interface to capture on. Exiting!")
        sys.exit(1)
    if not args.duration:
        args.duration = 60
    if args.duration < 10:
        args.duration = 60
        print("Too low of a duration set. Setting duration to 60 seconds")

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
    start(args.interface, args.duration, should_label=label, api_key=api_key, env_var=environment_variable,
          labeling_path=labeling_binary_path)
