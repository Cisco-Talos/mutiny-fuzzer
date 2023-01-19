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
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS 'AS IS' AND ANY
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
#
# Class to hold fuzzer data (.fuzzer file info)
# Can read/write .fuzzer files from an instantiation
#
#------------------------------------------------------------------

from backend.fuzzer_types import MessageCollection, Message
from backend.menu_functions import validate_number_range
import os.path
import sys

class FuzzerData(object):
    # Init creates fuzzer data and populates with defaults
    # readFromFile to load a .fuzzer file
    def __init__(self):
        # All messages in the conversation
        self.message_collection = MessageCollection()
        # Directory containing custom processors (Exception, Message, Monitor)
        # or 'default'
        self.processor_directory = 'default'
        # Number of times a test case causing a crash should be repeated
        self.failure_threshold = 3
        # How long to wait between retests
        self.failure_timeout = 5
        # Protocol (TCP, UDP)
        self.proto = 'tcp'
        # Port to use
        self.target_port = 0
        # Source port to use, -1 = auto
        self.source_port = -1
        # Source IP to use, 0.0.0.0 or '' is default/automatic
        self.source_ip = '0.0.0.0'
        # Whether to perform a test run
        self.should_perform_test_run = True
        # How long to time out on receive() (seconds)
        self.receive_timeout = 1.0
        # Dictionary to save comments made to a .fuzzer file.  Only really does anything if 
        # using readFromFile and then writeToFile in the same program
        # (For example, fuzzerconverter)
        self.comments = {}
        # Kind of kludgy string for use in read_from_fd, made global to not have to pass around
        # Details in read_from_fd()
        self._read_comments = ''
        # Update for compatibilty with new Decept
        self.messages_to_fuzz = [] 
    
    
    # Read in the FuzzerData from the specified .fuzzer file
    def read_from_file(self, file_path: str, quiet: bool = False):
        with open(file_path, 'r') as input_file:
            self.read_from_fd(input_file, quiet=quiet)
    
    # Utility function to fix up self.comments and self._read_comments within read_from_fd()
    # as data is read in
    def _push_comments(self, comment_section_name):
        self.comments[comment_section_name] = self._read_comments
        self._read_comments = ''

    # Same as above, but appends to existing comment section if possible
    def _append_comments(self, comment_section_name):
        if comment_section_name in self.comments:
            self.comments[comment_section_name] += self._read_comments
        else:
            self.comments[comment_section_name] = self._read_comments
        self._read_comments = ''

    # Update for compatibilty with newer versions of Decept.
    
    
    # Read in the FuzzerData from a specific file descriptor
    # Most usefully can be used to read from stdout by passing
    # sys.stdin
    def read_from_fd(self, file_descriptor, quiet=False):
        message_num = 0
        
        # This is used to track multiline messages
        last_message = None
        # Build up comments in this string until we're ready to push them out to the dictionary
        # Basically, we build lines and lines of comments, then when a command is encountered,
        # push them into the dictionary using that command as a key
        # Thus, when we go to write them back out, we can print them all before a given key
        self._read_comments = ''
        
        for line in file_descriptor:
            # Record comments on read so we can play them back on write if applicable
            if line.startswith('#') or line == '\n':
                self._read_comments += line
                # Skip all further processing for this line
                continue
            
            line = line.replace('\n', '')
            
            # Skip comments and whitespace
            if not line.startswith('#') and not line == '' and not line.isspace():
                args = line.split(' ')
                
                # Populate FuzzerData obj with any settings we can parse out
                try:
                    if args[0] == 'processor_dir':
                        self.processor_directory = args[1]
                        self._push_comments('processor_dir')
                    elif args[0] == 'failure_threshold':
                        self.failure_threshold = int(args[1])
                        self._push_comments('failure_threshold')
                    elif args[0] == 'failure_timeout':
                        self.failure_timeout = int(args[1])
                        self._push_comments('failure_timeout')
                    elif args[0] == 'proto':
                        self.proto = args[1]
                        self._push_comments('proto')
                    elif args[0] == 'port':
                        self.target_port = int(args[1])
                        self._push_comments('port')
                    elif args[0] == 'source_port':
                        self.source_port = int(args[1])
                        self._push_comments('source_port')
                    elif args[0] == 'source_ip':
                        self.source_ip = args[1]
                        self._push_comments('source_ip')
                    elif args[0] == 'should_perform_test_run':
                        # Use 0 or 1 for setting
                        if args[1] == '0':
                            self.should_perform_test_run = False
                        elif args[1] == '1':
                            self.should_perform_test_run = True
                        else:
                            raise RuntimeError('should_perform_test_run must be 0 or 1')
                        self._push_comments('should_perform_test_run')
                    elif args[0] == 'receive_timeout':
                        self.receive_timeout = float(args[1])
                        self._push_comments('receive_timeout')
                    elif args[0] == 'messages_to_fuzz':
                        print('WARNING: It looks like you\'re using a legacy .fuzzer file with messages_to_fuzz set.  This is now deprecated, so please update to the new format')
                        self.messages_to_fuzz = validate_number_range(args[1], flatten_list=True)
                        # Slight kludge: store comments above messages_to_fuzz with the first message.  *shrug*
                        # Comment saving is best effort anyway, right?
                        self._push_comments('message0')
                    elif args[0] == 'unfuzzedBytes':
                        print('ERROR: It looks like you\'re using a legacy .fuzzer file with unfuzzedBytes set.  This has been replaced by the new multi-line format.  Please update your .fuzzer file.')
                        sys.exit(-1)
                    elif args[0] == 'inbound' or args[0] == 'outbound':
                        message = Message()
                        message.set_from_serialized(line)
                        self.message_collection.add_message(message)
                        # Legacy code to handle old messages_to_fuzz format
                        if message_num in self.messages_to_fuzz:
                            message.isFuzzed = True
                        if not quiet:
                            print('\tMessage #{0}: {1} bytes {2}'.format(message_num, len(message.get_original_message()), message.direction))
                        self._push_comments('message{0}'.format(message_num))
                        message_num += 1
                        last_message = message
                    # 'sub' means this is a subcomponent
                    elif args[0] == 'sub':
                        if not 'message' in locals():
                            print('\tERROR: \'sub\' line declared before any \'message\' lines, throwing subcomponent out: {0}'.format(line))
                        else:
                            message.append_from_serialized(line)
                            if not quiet:
                                print('\t\tSubcomponent: {1} additional bytes'.format(message_num, len(message.subcomponents[-1].message)))
                    elif line.lstrip()[0] == "'" and 'message' in locals():
                        # If the line begins with ' and a message line has been found,
                        # assume that this is additional message data
                        # (Different from a subcomponent because it can't have additional data 
                        # tacked on)
                        message.append_from_serialized(line.lstrip(), create_new_subcomponent=False)
                    else:
                        if not quiet:
                            print('Unknown setting in .fuzzer file: {0}'.format(args[0]))
                    # Slap any messages between 'message' and 'sub', etc (ascii same way) above message
                    # It's way too annoying to print these out properly, as they get
                    # automagically outserialized by the Message object
                    # Plus they may change... eh, forget it, user can fix up themselves if they want
                    self._append_comments('message{0}'.format(message_num-1))
                except Exception as e:
                    print('Invalid line: {0}'.format(line))
                    raise e
        # Catch any comments below the last line
        self._push_comments('endcomments')
                        
    def _get_comments(self, comment_section_name):
        '''
        Utility function to get comments for a section after checking if they exist
        If not, returns ''
        '''
        if comment_section_name in self.comments:
            return self.comments[comment_section_name]
        else:
            return ''

    # Set messages_to_fuzz from string (such as '1,3-4')
    def set_messages_to_fuzz_from_string(self, messages_to_fuzz_str):
        self.messages_to_fuzz = validate_number_range(messages_to_fuzz_str, flatten_list=True)
        #print self._messages_to_fuzz

    
    # Write out the FuzzerData to the specified .fuzzer file
    def write_to_file(self, file_path, default_comments=False, final_message_num=-1):
        orig_file_path = file_path
        tail = 0
        while os.path.isfile(file_path):
            tail += 1
            file_path = '{0}-{1}'.format(orig_file_path, tail)
            # print 'File %s already exists' % (file_path,)
        
        if orig_file_path != file_path:
            print(('File {0} already exists, using {1} instead'.format(orig_file_path, file_path)))

        with open(file_path, 'w') as output_file:
            self.write_to_fd(output_file, default_comments=default_comments, final_message_num=final_message_num)
        
        return file_path

    # Write out the FuzzerData to a specific file descriptor
    # Most usefully can be used to write to stdout by passing
    # sys.stdout
    def write_to_fd(self, file_descriptor, default_comments=False, final_message_num=-1):
        if not default_comments and 'start' in self.comments:
            file_descriptor.write(self.comments['start'])
        
        # Processor Directory
        if default_comments:
            comment = '# Directory containing any custom exception/message/monitor processors\n'
            comment += '# This should be either an absolute path or relative to the .fuzzer file\n'
            comment += '# If set to \'default\', Mutiny will use any processors in the same\n'
            comment += '# folder as the .fuzzer file\n'
            file_descriptor.write(comment)
        else:
            file_descriptor.write(self._get_comments('processor_dir'))
        file_descriptor.write('processor_dir {0}\n'.format(self.processor_directory))
        
        # Failure Threshold
        if default_comments:
            file_descriptor.write('# Number of times to retry a test case causing a crash\n')
        else:
            file_descriptor.write(self._get_comments('failure_threshold'))
        file_descriptor.write('failure_threshold {0}\n'.format(self.failure_threshold))
        
        # Failure Timeout
        if default_comments:
            file_descriptor.write('# How long to wait between retrying test cases causing a crash\n')
        else:
            file_descriptor.write(self._get_comments('failure_timeout'))
        file_descriptor.write('failure_timeout {0}\n'.format(self.failure_timeout))
        
        # Receive Timeout
        if default_comments:
            file_descriptor.write('# How long for recv() to block when waiting on data from server\n')
        else:
            file_descriptor.write(self._get_comments('receive_timeout'))
        file_descriptor.write('receive_timeout {0}\n'.format(self.receive_timeout))
        
        # Should Perform Test Run
        if default_comments:
            file_descriptor.write('# Whether to perform an unfuzzed test run before fuzzing\n')
        else:
            file_descriptor.write(self._get_comments('should_perform_test_run'))
        sPTR = 1 if self.should_perform_test_run else 0
        file_descriptor.write('should_perform_test_run {0}\n'.format(sPTR))
        
        # Protocol
        if default_comments:
            file_descriptor.write('# Protocol (udp or tcp)\n')
        else:
            file_descriptor.write(self._get_comments('proto'))
        file_descriptor.write('proto {0}\n'.format(self.proto))
        
        # Port
        if default_comments:
            file_descriptor.write('# Port number to connect to\n')
        else:
            file_descriptor.write(self._get_comments('port'))
        file_descriptor.write('port {0}\n'.format(self.target_port))
        
        # Source Port
        if default_comments:
            file_descriptor.write('# Port number to connect from\n')
        else:
            file_descriptor.write(self._get_comments('source_port'))
        file_descriptor.write('source_port {0}\n'.format(self.source_port))

        # Source IP
        if default_comments:
            file_descriptor.write('# Source IP to connect from\n')
        else:
            file_descriptor.write(self._get_comments('source_ip'))
        file_descriptor.write('source_ip {0}\n\n'.format(self.source_ip))

        # Messages
        if final_message_num == -1:
            final_message_num = len(self.message_collection.messages)-1
        if default_comments:
            file_descriptor.write('# The actual messages in the conversation\n# Each contains a message to be sent to or from the server, printably-formatted\n')
        for i in range(0, final_message_num+1):
            message = self.message_collection.messages[i]
            if not default_comments:
                file_descriptor.write(self._get_comments('message{0}'.format(i)))
            file_descriptor.write(message.get_serialized())
            
        
        if not default_comments:
            file_descriptor.write(self._get_comments('endcomments'))
