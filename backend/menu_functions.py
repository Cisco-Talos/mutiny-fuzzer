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

# used during the mutiny_prep.py .fuzzer generation
# asks for and returns a boolean
def prompt(question, answers=["y", "n"], defaultIndex=None):
    answer = ""
    while answer not in answers:
        print("%s (%s)" % (question, "/".join(answers)))
        if defaultIndex != None:
            answer = input("Default %s: " % (answers[defaultIndex]))
        else:
            answer = input("No default: ")
        # Pretty up responses with a newline after
        print("")

        if defaultIndex != None and answer == "":
            answer = answers[defaultIndex]
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
def promptInt(question, defaultResponse=None, allowNo=False):
    answer = None

    while answer == None:
        print("%s" % (question))
        try:
            if defaultResponse:
                answer = input("Default {0}: ".format(defaultResponse)).strip()
            else:
                answer = input("No default: ")
            # Pretty up responses with a newline after
            print("")
            
            if allowNo and (answer == "n" or answer == ""):
                return None
            else:
                answer = int(answer)

        except ValueError:
            answer = None

        if answer == None and defaultResponse:
            answer = defaultResponse
    
    return answer

# Return input given as string if it passes the validationFunction test, else return None.
# If there is not validationFunc given, only return string.
# Return default repsonse if empty, the defaultResponse or Ctrl-C are given.
def promptString(question, defaultResponse="n", validateFunc=None):
    retStr = ""
    while not retStr or not len(retStr): 
        if defaultResponse:
            inputStr = input("%s\nDefault %s: " % (question, defaultResponse))
        else:
            inputStr = input("%s\nNo default: " % (question))
            
        # Pretty up responses with a newline after
        print("")
        if defaultResponse and (inputStr == defaultResponse or not len(inputStr)):
            return defaultResponse    
        # If we're looking for a specific format, validate
        # Validate functions must return None on failure of validation,
        # and != None on success
        if validateFunc:
            if validateFunc(inputStr):
                retStr = inputStr 

    return retStr 

# Takes a string of numbers, seperated via commas
# or by hyphens, and generates an appropriate list of
# numbers from it.
# e.g. str("1,2,3-6")  => list([1,2,xrange(3,7)])
#
# If flattenList=True, will return a list of distinct elements
#
# If given an invalid number string, returns None
def validateNumberRange(inputStr, flattenList=False):
    retList = []
    tmpList = [_f for _f in inputStr.split(',') if _f]

    # Print msg if invalid chars/typo detected
    for num in tmpList:
        try:
            retList.append(int(num))
        except ValueError:
            if '-' in num:
                intRange = num.split('-')                  
                # Invalid x-y-z
                if len(intRange) > 2:
                    print("Invalid range given")
                    return None
                try:
                    if not flattenList:
                        # Append iterator with bounds = intRange
                        retList.append(range(int(intRange[0]),int(intRange[1])+1)) 
                    else:
                        # Append individual elements
                        retList.extend(list(range(int(intRange[0]),int(intRange[1])+1))) 
                except TypeError:
                    print("Invalid range given")
                    return None
            else:
                print("Invalid number given")
                return None
    # All elements in the range are valid integers or integer ranges
    if flattenList:
        # If list is flattened, every element is an integer
        retList = sorted(list(set(retList)))
    return retList 

