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
#
# Utility functions for interactive scripts
#
#------------------------------------------------------------------

# Print success message in green
def print_success(message):
    SUCCESS = "\033[92m"
    CLEAR = "\033[00m"
    print(f'{SUCCESS}{message}{CLEAR}')

# Print warnings in yellow
# Copy pasta of CLEAR just to avoid finding a place to park defines / creating a class
def print_warning(message):
    WARNING = "\033[93m"
    CLEAR = "\033[00m"
    print(f'{WARNING}{message}{CLEAR}')

# Print errors in red
def print_error(message):
    ERROR = "\033[91m"
    CLEAR = "\033[00m"
    print(f'{ERROR}{message}{CLEAR}')

# used during the mutiny_prep.py .fuzzer generation
# asks for and returns a boolean
def prompt(question, answers=["y", "n"], default_index=None):
    answer = ""
    while answer not in answers:
        print("%s (%s)" % (question, "/".join(answers)))
        if default_index != None:
            answer = get_input("Default %s: " % (answers[default_index]))
        else:
            answer = get_input("No default: ")
        # Pretty up responses with a newline after
        print("")

        if default_index != None and answer == "":
            answer = answers[default_index]
            break

    if len(answers) == 2 and answers[0] == "y" and answers[1] == "n":
        if answer == "y":
            return True
        else:
            return False
    else:
        return answer

# used during the mutiny_prep.py .fuzzer generation
# asks for and returns an integer
def prompt_int(question, default_response=None, allow_no=False):
    answer = None

    while answer == None:
        print("%s" % (question))
        try:
            if default_response:
                answer = get_input("Default {0}: ".format(default_response)).strip()
            else:
                answer = get_input("No default: ")
            # Pretty up responses with a newline after
            print("")
            
            if allow_no and (answer == "n" or answer == ""):
                return None
            else:
                answer = int(answer)

        except ValueError:
            answer = None

        if answer == None and default_response:
            answer = default_response
    
    return answer

# Return input given as string if it passes the validationFunction test, else return None.
# If there is not validationFunc given, only return string.
# Return default repsonse if empty, the default_response or Ctrl-C are given.
def prompt_string(question, default_response="n", validate_func=None):
    ret_str = ""
    while not ret_str or not len(ret_str): 
        if default_response:
            input_str = get_input("%s\nDefault %s: " % (question, default_response))
        else:
            input_str = get_input("%s\nNo default: " % (question))
            
        # Pretty up responses with a newline after
        print("")
        if default_response and (input_str == default_response or not len(input_str)):
            return default_response    
        # If we're looking for a specific format, validate
        # Validate functions must return None on failure of validation,
        # and != None on success
        if validate_func:
            if validate_func(input_str):
                ret_str = input_str 
        else:
            ret_str = input_str

    return ret_str 

def get_input(prompt):
    '''
    wrapper of input() so it can be stubbed out in tests
    '''
    return input(prompt)

def validate_number_range(input_str: str, flatten_list: bool = False):
    '''
    Takes a string of numbers, seperated via commas
    or by hyphens, and generates an appropriate list of
    numbers from it.
    e.g. str("1,2,3-6")  => list([1,2,xrange(3,7)])

    If flatten_list=True, will return a list of distinct elements

    If given an invalid number string, returns None
    '''
    ret_list = []
    tmp_list = [_f for _f in input_str.split(',') if _f]

    # Print msg if invalid chars/typo detected
    for num in tmp_list:
        try:
            ret_list.append(int(num))
        except ValueError:
            if '-' in num:
                int_range = num.split('-')                  
                # Invalid x-y-z
                if len(int_range) > 2:
                    print("Invalid range given")
                    return None
                try:
                    if not flatten_list:
                        # Append iterator with bounds = int_range
                        ret_list.append(range(int(int_range[0]),int(int_range[1])+1)) 
                    else:
                        # Append individual elements
                        ret_list.extend(list(range(int(int_range[0]),int(int_range[1])+1))) 
                except TypeError:
                    print("Invalid range given")
                    return None
            else:
                print("Invalid number given")
                return None
    # All elements in the range are valid integers or integer ranges
    if flatten_list:
        # If list is flattened, every element is an integer
        ret_list = sorted(list(set(ret_list)))
    return ret_list 

