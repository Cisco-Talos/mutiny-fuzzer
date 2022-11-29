#------------------------------------------------------------------

# Prep traffic log for fuzzing
#
# Cisco Confidential
# November 2014, created within ASIG
# Author James Spadaro (jaspadar)
# Contributor Lilith Wyatt (liwyatt)
#
# Copyright (c) 2014-2015 by Cisco Systems, Inc.
# All rights reserved.
#
# takes pcap or c_arrays output from Wireshark and 
# processes it into a .fuzzer file for use with mutiny.py
#------------------------------------------------------------------


import os
import sys
# including root project directory in path
current = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(current)
sys.path.append(parent)
import argparse
from backend.fuzzer_types import Message, MessageCollection, Logger
from backend.menu_functions import prompt, prompt_int, prompt_string, validate_number_range, print_success, print_warning, print_error
from backend.fuzzer_data import FuzzerData
from backend.packets import PROTO
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all

class MutinyPrep(object):
    class ProcessingState:
        Between = 0
        Reading = 2
        Combining = 3

    def __init__(self, args):
        self.last_message_direction = -1
        self.force_defaults = args.force
        self.dump_ascii = args.dump_ascii
        self.input_file_path = args.pcap_file
        self.default_port = None
        self.fuzzer_data = FuzzerData()
        self.fuzzer_data.processor_directory = args.processor_dir[0]
        # Did the user specify the -raw flag to do L2?
        self.is_raw = args.raw
        self.use_macs = self.is_raw
        # If it's C Arrays, we ask for the protocol in the prompts
        self.c_array = False
        pass

    def prep(self):
        '''
        facilitates
        1. processing of user specified pcap or C_array file
        2. user configuration of .fuzzer format
        3. creation of the .fuzzer file
        '''
        self._process_input_file() # extract inputData from input file
        self._gen_fuzz_config() # prompt user for .fuzzer configuration preferences
        self._write_fuzzer_file() # write .fuzzer file


    def _process_input_file(self):
        '''
        Processes input files by opening them and dispatching a pcap ingestor. if pcap ingestor fails,
        attempts to dispach a c_array ingestor
        '''
        print("Processing %s..." % (self.input_file_path))
        try:
            self._process_pcap() # Process as Pcap preferentially
        except Exception as rdpcap_e:
            print_error("Failed to process as PCAP: " +  str(rdpcap_e))
            self.c_array = True
            print("Processing as c_array...")
            try:
                self._process_c_array()
            except Exception as e:
                print_error('''Can't parse as pcap or c_arrays:''')
                print_error(f'Pcap parsing error: {str(rdpcap_e)}')
                print_error(f'Not valid c_arrays: {str(e)}')
                pass

        if len(self.fuzzer_data.message_collection.messages) == 0:
            print_error('\nCouldn\'t process input file - are you sure you gave a file containing a tcpdump pcap or wireshark c_arrays?')
            exit()

        print_success(f'Processed input file {self.input_file_path}')


    def _process_pcap(self, test_port: int = None, test_mac: str = None, combine_packets: bool = None):
        '''
        ingests pcap using scapy and parses client-server communication to populate self.fuzzer_data 
        with message sequences that we can use as a baseline for our fuzzing
        params:
            test_port: (optional) used for testing to stub out the calls to prompt() for port selection
            test_mac: (optional) used for testing to stub out the calls to prompt() for mac selection
            combine_packets: (optional) used for testing to stub out the calls to prompt for combining packets selection
        '''
        client_port = None
        server_port = None
        client_mac = None
        server_mac = None
        
        input_data = scapy.all.rdpcap(self.input_file_path)
        message = Message()
        temp_message_data = ""
        # Allow combining packets in same direction back-to-back into one message
        asked_to_combine_packets = False
        is_combining_packets = False

        j = -1
        for i in range(0, len(input_data)):
            try:
                if i == 0: # first packet
                    # returns port or mac dependent upon protocol
                    client_data, server_data = self._process_first_pcap_packet(input_data[i], test_port, test_mac)
                    if self.use_macs:
                        client_mac = client_data
                        server_mac = server_data
                    else:
                        client_port = client_data
                        server_port = server_data
                elif not self.use_macs and input_data[i].sport not in [client_port, server_port]:
                    print_error(f'Error: unknown source port {inputData[i].sport} - is the capture filtered to a single stream?')
                elif not self.use_macs and input_data[i].dport not in [client_port, server_port]:
                # TODO: we don't have any sort of checking to make sure a l2raw capture is single stream 
                    print_error(f'Error: unknown destination port {inputData[i].dport} - is the capture filtered to a single stream?')
                if not self.use_macs:
                    new_message_direction = Message.Direction.Outbound if input_data[i].sport == client_port else Message.Direction.Inbound
                else:
                    new_message_direction = Message.Direction.Outbound if input_data[i].src == client_mac else Message.Direction.Inbound

                if self.fuzzer_data.proto == 'udp':
                    # This appear to work for UDP.  Go figure, thanks scapy.
                    temp_message_data = bytes(input_data[i].payload.payload.payload)
                elif self.fuzzer_data.proto == 'tcp': 
                    # This appears to work for TCP
                    temp_message_data = bytes(input_data[i].payload.payload.payload)
                    if temp_message_data == b'': continue
                elif self.fuzzer_data.proto == 'L2raw': 
                    temp_message_data = bytes(input_data[i])
                else:
                    print_error(f'Error: Fuzzer data has an unknown protocol {FUZZER_DATA.proto} - should be impossible?')
                    exit()

                if new_message_direction == self.last_message_direction:
                    if self.force_defaults:
                       is_combining_packets = True 
                       asked_to_combine_packets = True
                    if not asked_to_combine_packets:
                        if combine_packets is not None:
                            is_combining_packets = combine_packets
                        else:
                            is_combining_packets =  prompt("There are multiple packets from client to server or server to client back-to-back - combine payloads into single messages?")
                        asked_to_combine_packets = True
                    if is_combining_packets:
                        message.append_message_from(Message.Format.Raw, bytearray(temp_message_data), False)
                        print_success("\tMessage #%d - Added %d new bytes %s" % (j, len(tempMessageData), message.direction))
                        continue
                # Either direction isn't the same or we're not combining packets
                message = Message()
                message.direction = new_message_direction
                self.last_message_direction = new_message_direction
                message.set_message_from(Message.Format.Raw, bytearray(temp_message_data), False)
                self.fuzzer_data.message_collection.add_message(message)
                j += 1
                print_success("\tMessage #%d - Processed %d bytes %s" % (j, len(message.getOriginalMessage()), message.direction))
            except AttributeError:
                # No payload, keep going (different from empty payload)
                continue


    def _process_first_pcap_packet(self, packet, test_port, test_mac):
        dst_port = None
        src_port = None
        dst_mac = None
        src_mac = None
        if self.is_raw:
            self.fuzzer_data.proto = 'L2raw'
            self.use_macs = True
            print('Pulling layer 2+ data from pcap to use with raw sockets')
        else:
            if packet.proto == PROTO['udp']:
                self.fuzzer_data.proto = 'udp'
                print('Protocol is UDP')
            elif packet.proto == PROTO['tcp']:
                self.fuzzer_data.proto = 'tcp'
                print('Protocol is TCP')
            else:
                print_error(f'Error: First packet has protocol {inputData[i].proto} - Did you mean to set "--raw" for Layer 2 fuzzing?')
                exit()
            # is not a raw socket, can grab ports
            # First packet will usually but not always come from client
            # Use port instead of ip/MAC in case we're fuzzing on the same machine as the daemon
            # Guess at right port based, confirm to user
            src_port = packet.sport
            dst_port = packet.dport
            # If port1 == port2, then it can't be the same ip/MAC, so go based on that
            if src_port == dst_port:
                print("Source and destination ports are the same, using MAC addresses to differentiate server and client.")
                self.use_macs = True
        # either raw or ports are the same
        if self.use_macs:
            src_mac = packet.src
            dst_mac = packet.dst
            server_mac = dst_mac
            if not self.force_defaults:
                if test_mac:
                    server_mac = test_mac
                else:
                    server_mac = prompt("Which mac corresponds to the server?", [str(src_mac), str(dst_mac)], default_index=1)
            client_mac = src_mac if server_mac == dst_mac else dst_mac
            return client_mac, server_mac
        else:
            # under assumption that client sent first packet 
            server_port = dst_port
            if not self.force_defaults: 
                if test_port:
                    server_port = test_port
                else:
                    server_port = int(prompt("Which port is the server listening on?", [str(dst_port), str(src_port)], default_index=0 if src_port > dst_port else 1))

            client_port = src_port if server_port == dst_port else dst_port
            self.default_port = server_port
            return client_port, server_port



    def _process_c_array(self, combine_packets: bool = None):
        '''
        Process and convert c_array into .fuzzer
        This is processing the wireshark syntax looking like:

        char peer0_0[] = { 0x66, 0x64, 0x73, 0x61, 0x0a };
        char peer1_0[] = { 0x61, 0x73, 0x64, 0x66, 0x0a };

        First is message from client to server, second is server to client
        Format is peer0/1_messagenum
        0 = client, 1 = server
        '''

        self.last_message_direction = -1
        state = self.ProcessingState.Between # Track what we're looking for
        # Allow combining packets in same direction back-to-back into one message
        asked_to_combine_packets = False
        is_combining_packets = False

        with open(self.input_file_path, 'r') as input_file:
            i = 0
            for line in input_file:
                #remove comments
                com_start, com_end = line.find('/*'),line.rfind('*/')
                if com_start > -1 and com_end > -1:
                    line = line[:com_start] + line[com_end+2:]

                if state == self.ProcessingState.Between:
                    # On a new message, seek inputData
                    message = Message()
                    temp_message_data = ""
                    
                    peer_pos = line.find("peer")
                    if peer_pos == -1:
                        continue
                    elif line[peer_pos+4] == str(0):
                        message.direction = Message.Direction.Outbound
                    elif line[peer_pos+4] == str(1):
                        message.direction = Message.Direction.Inbound
                    else:
                        continue
                    
                    brace_pos = line.find("{")
                    if brace_pos == -1:
                        continue
                    temp_message_data += line[brace_pos+1:]
                    state = self.ProcessingState.Reading
                    
                    # Sometimes HTTP requests, etc, get separated into multiple packets but they should
                    # really be treated as one message.  Allow the user to decide to do this automatically
                    if message.direction == self.last_message_direction:
                        if self.force_defaults:
                            asked_to_combine_packets=True
                            is_combining_packets=True
                        if not asked_to_combine_packets:
                            if combine_packets is not None:
                                is_combining_packets = combine_packets
                            else:
                                is_combining_packets = prompt("There are multiple packets from client to server or server to client back-to-back - combine payloads into single messages?")
                            asked_to_combine_packets = True
                        if is_combining_packets:
                            message = self.fuzzer_data.message_collection.messages[-1]
                            state = self.ProcessingState.Combining
                elif state == self.ProcessingState.Reading or state == self.ProcessingState.Combining:
                    brace_pos = line.find("}")
                    if brace_pos == -1:
                        # No close brace means keep reading
                        temp_message_data += line
                    else:
                        # Close brace means save the message
                        temp_message_data += line[:brace_pos]
                        # Turn list of comma&space-separated bytes into a string of 0x hex bytes
                        message_array = temp_message_data.replace(",", "").replace("0x", "").split()
                        if state == self.ProcessingState.Reading:
                            message.set_message_from(Message.Format.Comma_Separated_Hex, ",".join(message_array), False)
                            self.fuzzer_data.message_collection.add_message(message)
                            print("\tMessage #%d - Processed %d bytes %s" % (i, len(message_array), message.direction))
                        elif state == self.ProcessingState.Combining:
                            # Append new inputData to last message
                            i -= 1
                            message.append_message_from(Message.Format.Comma_Separated_Hex, ",".join(message_array), False, create_new_subcomponent=False)
                            print("\tMessage #%d - Added %d new bytes %s" % (i, len(message_array), message.direction))
                        if self.dump_ascii:
                            print("\tAscii: %s" % (str(message.get_original_message())))
                        i += 1
                        state = self.ProcessingState.Between
                        self.last_message_direction = message.direction


    def _gen_fuzz_config(self, failure_threshold: int = None, failure_timeout: int = None, proto: str = None, port: int = None):
        '''
        get fuzzing details 
        '''

        if self.force_defaults:
            self.fuzzer_data.target_port = self.default_port
            self.fuzzer_data.failure_threshold = 3
            self.fuzzer_data.failure_timeout = 5
        else:
            # ask how many times we should repeat a failed test, as in one causing a crash
            self.fuzzer_data.failure_threshold = failure_threshold if failure_threshold else prompt_int("\nHow many times should a test case causing a crash or error be repeated?", default_response=3)
            # timeout between failure retries
            self.fuzzer_data.failure_timout = failure_timout if failure_timout else prompt_int("When the test case is repeated above, how many seconds should it wait between tests?", default_response=5)
            if not self.is_raw:
                # port number to connect on
                self.fuzzer_data.target_port = port if port else prompt_int("What port should the fuzzer %s?" % ("connect to"), default_response=self.default_port)
            
            # For pcaps, we pull protocol from the pcap itself
            if self.c_array:
                if self.is_raw:
                    self.fuzzer_data.proto = "L2raw"
                else:
                    # ask if tcp or udp
                    self.fuzzer_data.proto = proto if proto else prompt("Which protocol?", answers=["tcp", "udp"], default_index=0)

        if not self.is_raw and self.fuzzer_data.target_port == None:
            # address case where CArray does not set default port
            self.fuzzer_data.target_port = -1
            while(self.fuzzer_data.target_port <= 0 or self.fuzzer_data.target_port >= 65535):
                self.fuzzer_data.target_port = prompt_int("What port should the fuzzer %s?" % ("connect to"))



    def _write_fuzzer_file(self, auto_gen: bool = None):
        '''
        writes self.fuzzer_data to a new .fuzzer file using prompt_and_output()
        '''
        # see if they'd like us to just rip out a .fuzzer per client message
        # default to no
        auto_gen = auto_gen if auto_gen is not None else prompt("\nWould you like to auto-generate a .fuzzer for each client message?", default_index=1)
        if auto_gen:
            self._prompt_and_output(self._get_next_message(0, Message.Direction.Outbound), auto_generate_all_client=True)
        else:
            # always run once
            output_message_num = self._prompt_and_output(self._get_next_message(0, Message.Direction.Outbound))

            # allow creating multiple .fuzzers afterwards
            if not self.force_defaults:
                while prompt("\nDo you want to generate a .fuzzer for another message number?", default_index=1):
                    output_message_num = self._prompt_and_output(output_message_num)

        print_success('All files have been written.')

    def _get_next_message(self, start_message: int, message_direction: Message.Direction):
        '''
        helper function to get next message from either client or server
        inclusive (if startmessage is fromclient and so is direction,
        will return startmessage)
        returns message number or none if no messages remain
        '''
        i = start_message
        
        while i < len(self.fuzzer_data.message_collection.messages):
            if self.fuzzer_data.message_collection.messages[i].direction == message_direction:
                return i
            i += 1
        
        return None

    def _prompt_and_output(self, output_message_num: int, auto_generate_all_client: bool = False, final_msg_num: int = None, msgs_to_fuzz: str = None):
        '''
        prompt for .fuzzer-specific questions and write file (calls above function)
        allows us to let the user crank out a bunch of .fuzzer files quickly
        output_message_num is the highest message output last time, if they're creating multiple .fuzzer files
        auto_generate_all_client will make a .fuzzer file per client automatically
        '''
        # how many of the messages to output to the .fuzzer
        if self.force_defaults or auto_generate_all_client:
            final_message_num = len(self.fuzzer_data.message_collection.messages) - 1
        else:
            if len(self.fuzzer_data.message_collection.messages) == 1:
                final_message_num = 0
            else:
                final_message_num = final_msg_num if final_msg_num else prompt_int("What is the last message number you want output?", default_response=len(self.fuzzer_data.message_collection.messages)-1)

        # any messages previously marked for fuzzing, unmark first
        # inefficient as can be, but who cares
        for message in self.fuzzer_data.message_collection.messages:
            if message.is_fuzzed:
                message.is_fuzzed = False
                for subcomponent in message.subcomponents:
                    subcomponent.is_fuzzed = False
        
        if not auto_generate_all_client:
            messages_to_fuzz = ''
            while len(messages_to_fuzz) <= 0 :
                messages_to_fuzz = msgs_to_fuzz if msgs_to_fuzz else prompt_string("Which message numbers should be fuzzed? valid: 0-%d" % (final_message_num),default_response=str(output_message_num),validate_func=validate_number_range)
            # len of messages_to_fuzz must now be between 0 and final_message_num
            output_file_name_end = messages_to_fuzz
            # iterate through messages and set .is_fuzzed on subcomponents
            for message_index in validate_number_range(messages_to_fuzz, flatten_list=True):
                self.fuzzer_data.message_collection.messages[message_index].is_fuzzed = True
                for subcomponent in self.fuzzer_data.message_collection.messages[message_index].subcomponents:
                    subcomponent.is_fuzzed = True
        else:
            output_file_name_end = str(output_message_num)
            # set message at output_message_num and all subcomponents .is_fuzzed to true
            self.fuzzer_data.message_collection.messages[output_message_num].is_fuzzed = True
            for subcomponent in self.fuzzer_data.message_collection.messages[output_message_num].subcomponents:
                subcomponent.is_fuzzed = True

        # write out .fuzzer file
        output_file_path = "{0}-{1}.fuzzer".format(os.path.splitext(self.input_file_path)[0], output_file_name_end)
        actual_path = self.fuzzer_data.write_to_file(output_file_path, default_comments=True, final_message_num=final_message_num)
        
        # if we are fuzzing all client messages, continue to recursively call prompt_and_output for next message
        if auto_generate_all_client:
            next_message = self._get_next_message(output_message_num + 1, Message.Direction.Outbound)
            # will return none when we're out of messages to auto-output
            if next_message:
                self._prompt_and_output(next_message, auto_generate_all_client=True)
        return final_message_num


def parse_arguments():
    '''
    parse arguments for fuzzer file preparation
    '''
    desc =  '======== The Mutiny Fuzzing Framework ==========' 
    epi = '==' * 24 + '\n'
    parser = argparse.ArgumentParser(description=desc,epilog=epi)

    parser.add_argument('pcap_file', help='Pcap/c_array output from wireshark')
    parser.add_argument('-d','--processor_dir', help = 'Location of custom pcap Message/exception/log/monitor processors if any, see appropriate *processor.py source in ./mutiny_classes/ for implementation details', nargs=1, default=['default'])
    parser.add_argument('-a', '--dump_ascii', help='Dump the ascii output from packets ', action='store_true', default=False)
    parser.add_argument('-f', '--force', help='Take all default options', action = 'store_true', default=False) 
    parser.add_argument('-r', '--raw', help='Pull all layer 2+ data / create .fuzzer for raw sockets', action = 'store_true', default=False) 

    # stub out calls to input() and related test handling
    parser.add_argument('-t', '--testing', help='For use by test suite to stub calls to input() and perform related test handling', action='store_true')
    return parser.parse_args()


def main():
    if len(sys.argv) < 2:
        sys.argv.append('-h')
    args = parse_arguments()

    if not os.path.isfile(args.pcap_file):
        print_error(f'Cannot read input {args.pcap_file}')
        exit()

    fuzzer_file_prepper = MutinyPrep(args)
    fuzzer_file_prepper.prep()

if __name__ == '__main__':
    main()
