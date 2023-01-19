#!/usr/bin/env python
#------------------------------------------------------------------
# November 2014, created within ASIG
# Author James Spadaro (jaspadar)
# Co-Author Lilith Wyatt (liwyatt)
#------------------------------------------------------------------
# Copyright (c) 2014-2017 by Cisco Systems, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the Cisco Systems, Inc. nor the
#    names of its contributors may be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#------------------------------------------------------------------
# Type definitions for the fuzzer
#
# This script defines the various message and data types used in
# the fuzzer, and utility functions used by them.
#------------------------------------------------------------------
import ast
import os
import os.path
from copy import deepcopy
import codecs

class MessageSubComponent(object):
    def __init__(self, message: bytearray, is_fuzzed: bool):
        self.message = message
        self.is_fuzzed = is_fuzzed
        # This includes both fuzzed messages and messages the user
        # has altered with messageprocessor callbacks
        self._altered = message
    
    def set_altered_byte_array(self, byte_array: bytearray):
        self._altered = byte_array
    
    def get_altered_byte_array(self):
        return self._altered
    
    def get_original_byte_array(self):
        return self.message

# Contains all data of a given packet of the session            
class Message(object):
    class Direction:
        Outbound = "outbound"
        Inbound = "inbound"
    
    class Format:
        Comma_Separated_Hex = 0 # 00,01,02,20,2a,30,31
        Ascii = 1 # asdf\x00\x01\x02
        Raw = 2 # a raw byte array from a pcap
        
    def __init__(self):
        self.direction = -1
        # Whether any subcomponent is fuzzed - might not be entire message
        # Default to False, set to True as message subcomponents are set below
        self.is_fuzzed = False 
        # This will be populated with message subcomponents
        # IE, specified as message 0 11,22,33
        # 44,55,66
        # Then 11,22,33 will be subcomponent 0, 44,55,66 will be subcomponent 1
        # If it's a traditional message, it will only have one element (entire message)
        self.subcomponents = []

    def get_original_subcomponents(self):
        return [subcomponent.message for subcomponent in self.subcomponents]
    
    # May or may not have actually been changed
    # Version of subcomponents that includes fuzzing and messageprocessor changes from user
    # Is transient and reverted to original every iteration
    def get_altered_subcomponents(self):
        return [subcomponent.get_altered_byte_array() for subcomponent in self.subcomponents]
    
    def get_original_message(self):
        return bytearray().join([subcomponent.message for subcomponent in self.subcomponents])
    
    # May or may not have actually been changed
    # Version of message that includes fuzzing and messageprocessor changes from user
    # Is transient and reverted to original every iteration
    def get_altered_message(self):
        return bytearray().join([subcomponent.get_altered_byte_array() for subcomponent in self.subcomponents])
    
    def reset_altered_message(self):
        for subcomponent in self.subcomponents:
            subcomponent.set_altered_byte_array(subcomponent.message)
    
    # Set the message on the Message
    # source_type - Format.Comma_Separated_Hex, Ascii, or Raw
    # message - Message in above format
    # is_fuzzed - whether this message should have its subcomponent
    #   flag is_fuzzed set
    def set_message_from(self, source_type: Format, message, is_fuzzed: bool):
        if source_type == self.Format.Comma_Separated_Hex:
            message = message.replace(',', '')
            message = bytearray.fromhex(message)
        elif source_type == self.Format.Ascii:
            message = self.deserialize_byte_array(message)
        elif source_type == self.Format.Raw:
            message = message
        else:
            raise RuntimeError("Invalid source_type")
        
        self.subcomponents = [MessageSubComponent(message, is_fuzzed)]
        
        if is_fuzzed:
            self.is_fuzzed = True
    
    # Same arguments as above, but adds to .message as well as
    # adding a new subcomponent
    # create_new_subcomponent - If false, don't create another subcomponent,
    #   instead, append new message data to last subcomponent in message
    def append_message_from(self, source_type: Format, message, is_fuzzed: bool, create_new_subcomponent: bool = True):
        if source_type == self.Format.Comma_Separated_Hex:
            message = message.replace(',', '')
            new_message = bytearray.fromhex(message)
        elif source_type == self.Format.Ascii:
            new_message = self.deserialize_byte_array(message)
        elif source_type == self.Format.Raw:
            new_message = message
        else:
            raise RuntimeError("Invalid source_type")
        
        if create_new_subcomponent:
            self.subcomponents.append(MessageSubComponent(new_message, is_fuzzed))
        else:
            self.subcomponents[-1].message += new_message

        if is_fuzzed:
            # Make sure message is set to fuzz as well
            self.is_fuzzed = True
    
    def is_outbound(self):
        return self.direction == self.Direction.Outbound
    
    def __eq__(self, other):
        # bytearray (for message) implements __eq__()
        return self.direction == other.direction and self.message == other.message
    
    @classmethod
    def serialize_byte_array(cls, byte_array: bytearray):
        if type(byte_array) != bytearray:
            raise Exception(f'Argument to serialize_byte_array isn\'t a byte array: {byte_array}')
        return repr(bytes(byte_array))[1:] # Don't include leading 'b', clearer/easier in .fuzzer file
    
    @classmethod
    def deserialize_byte_array(cls, string: str):
        return bytearray(ast.literal_eval(f'b{string}'))
    
    def get_altered_serialized(self):
        if len(self.subcomponents) < 1:
            return "{0} {1}\n".format(self.direction, "ERROR: No data in message.")
        else:
            serialized_message = "{0}{1} {2}\n".format("fuzz " if self.subcomponents[0].is_fuzzed else "", self.direction, self.serialize_byte_array(self.subcomponents[0].get_altered_byte_array()))
            
            for subcomponent in self.subcomponents[1:]:
                serialized_message += "sub {0}{1}\n".format("fuzz " if subcomponent.is_fuzzed else "", self.serialize_byte_array(subcomponent.get_altered_byte_array()))
            
            return serialized_message
    
    def get_serialized(self):
        if len(self.subcomponents) < 1:
            return "{0} {1}\n".format(self.direction, "ERROR: No data in message.")
        else:
            serialized_message = "{0} {1}{2}\n".format(self.direction, "fuzz " if self.subcomponents[0].is_fuzzed else "", self.serialize_byte_array(self.subcomponents[0].message))
            
            for subcomponent in self.subcomponents[1:]:
                serialized_message += "sub {0}{1}\n".format("fuzz " if subcomponent.is_fuzzed else "", self.serialize_byte_array(subcomponent.message))
            
            return serialized_message

    # Utility function for set_from_serialized and append_from_serialized below
    def _extract_message_components(self, serialize_data):
        first_quote_single = serialize_data.find('\'')
        last_quote_single = serialize_data.rfind('\'')
        first_quote_double = serialize_data.find('"')
        last_quote_double = serialize_data.rfind('"')
        first_quote = -1
        last_quote = -1
        
        if first_quote_single == -1 or first_quote_single == last_quote_single:
            # If no valid single quotes, go double quote
            first_quote = first_quote_double
            last_quote = last_quote_double
        elif first_quote_double == -1 or first_quote_double == last_quote_double:
            # If no valid double quotes, go single quote
            first_quote = first_quote_single
            last_quote = last_quote_single
        elif first_quote_single < first_quote_double:
            # If both are valid, go single if further out
            first_quote = first_quote_single
            last_quote = last_quote_single
        else:
            # Both are valid but double is further out
            first_quote = first_quote_double
            last_quote = last_quote_double
        
        if first_quote == -1 or last_quote == -1 or first_quote == last_quote:
            raise RuntimeError("Invalid message data, no message found")

        # Pull out everything, quotes and all, and deserialize it
        message_data = serialize_data[first_quote:last_quote+1]
        # Process the args
        serialize_data = serialize_data[:first_quote].split(" ")
        
        return (serialize_data, message_data)
    
    # Handles _one line_ of data, either "inbound" or "outbound"
    # Lines following this should be passed to append_from_serialized() below
    def set_from_serialized(self, serialize_data):
        serialize_data = serialize_data.replace("\n", "")
        (serialize_data, message_data) = self._extract_message_components(serialize_data)
        
        if len(message_data) == 0 or len(serialize_data) < 1:
            raise RuntimeError("Invalid message data")
        
        direction = serialize_data[0]
        args = serialize_data[1:-1]
        
        if direction != "inbound" and direction != "outbound":
            raise RuntimeError("Invalid message data, unknown direction {0}".format(direction))
        
        is_fuzzed = False
        if "fuzz" in args:
            is_fuzzed = True
            if len(serialize_data) < 3:
                raise RuntimeError("Invalid message data")
        
        self.direction = direction
        self.set_message_from(self.Format.Ascii, message_data, is_fuzzed)
    
    # Add another line, used for multiline messages
    def append_from_serialized(self, serialize_data, create_new_subcomponent=True):
        serialize_data = serialize_data.replace("\n", "")
        (serialize_data, message_data) = self._extract_message_components(serialize_data)
        
        if create_new_subcomponent:
            if len(message_data) == 0 or len(serialize_data) < 1 or serialize_data[0] != "sub":
                raise RuntimeError("Invalid message data")
        else:
            # If not creating a subcomponent, we won't have "sub", "fuzz", and the other fun stuff
            if len(message_data) == 0:
                raise RuntimeError("Invalid message data")
        
        args = serialize_data[1:-1]
        # Put either "fuzz" or nothing before actual message
        # Can tell the difference even with ascii because ascii messages have '' quotes
        # IOW, even a message subcomponent 'fuzz' will have the 's around it, not be fuzz without quotes
        is_fuzzed = False
        if "fuzz" in args:
            is_fuzzed = True
        
        self.append_message_from(self.Format.Ascii, message_data, is_fuzzed, create_new_subcomponent=create_new_subcomponent)

class MessageCollection(object):
    def __init__(self):
        self.messages = []
    
    def add_message(self, message: Message):
        self.messages.append(message)
    
    def do_client_messages_match(self, other_message_collection):
        for i in range(0, len(self.messages)):
            # Skip server messages
            if not self.messages[i].is_outbound():
                continue
            try:
                # Message implements __eq__()
                if self.messages[i] != other_message_collection.messages[i]:
                    return False
            except IndexError:
                return False
        
        # All messages passed
        return True


# Handles all the logging of the fuzzing session
# Log messages can be found at sample_apps/<app>/<app>_logs/<date>/
class Logger(object):
    def __init__(self, folder_path):
        self._folder_path = folder_path
        if os.path.exists(folder_path):
            print("Data output directory already exists: %s" % (folder_path))
            exit()
        else:
            try:
                os.makedirs(folder_path)
            except:
                print("Unable to create logging directory: %s" % (folder_path))
                exit()

        self.reset_for_new_run()

    # Store just the data, forget trying to make a Message object
    # With the subcomponents and everything, it just gets weird, 
    # and we don't need it
    def set_received_message_data(self, message_number: int, data: object):
        self.received_message_data[message_number] = data

    def set_highest_message_number(self, message_number: int):
        # The highest message # this fuzz session made it to
        self._highest_message_number = message_number

    def output_last_log(self, run_number: int, message_collection: MessageCollection, error_message: str):
        return self._output_log(run_number, message_collection, error_message, self._last_received_message_data, self._last_highest_message_number)

    def output_log(self, run_number: int, message_collection: MessageCollection, error_message: str):
        return self._output_log(run_number, message_collection, error_message, self.received_message_data, self._highest_message_number)

    def _output_log(self, run_number: int, message_collection: MessageCollection, error_message: str, received_message_data: object, highest_message_number: int):
        with open(os.path.join(self._folder_path, str(run_number)), "w") as output_file:
            print("Logging run number %d" % (run_number))
            output_file.write("Log from run with seed %d\n" % (run_number))
            output_file.write("Error message: %s\n" % (error_message))

            if highest_message_number == -1 or run_number == 0:
                output_file.write("Failed to connect on this run.\n")

            output_file.write("\n")

            i = 0
            for message in message_collection.messages:
                output_file.write("Packet %d: %s" % (i, message.get_serialized()))

                if message.is_fuzzed:
                    output_file.write("Fuzzed Packet %d: %s\n" % (i, message.get_altered_serialized()))
                
                if i in received_message_data:
                    # Compare what was actually sent to what we expected, log if they differ
                    if received_message_data[i] != message.get_original_message():
                        output_file.write("Actual data received for packet %d: %s\n" % (i, Message.serialize_byte_array(received_message_data[i])))
                    else:
                        output_file.write("Received expected data\n")

                if highest_message_number == i:
                    if message.is_outbound():
                        output_file.write("This is the last message sent\n")
                    else:
                        output_file.write("This is the last message received\n")

                output_file.write("\n")
                i += 1

    def reset_for_new_run(self):
        try:
            self._last_received_message_data = deepcopy(self.received_message_data)
            self._last_highest_message_number = self._highest_message_number
        except AttributeError:
            self._last_received_message_data = {}
            self._last_highest_message_number = -1

        self.received_message_data = {}
        self.set_highest_message_number(-1)
