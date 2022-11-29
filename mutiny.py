#!/usr/bin/env python3
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
#
#------------------------------------------------------------------

import os
import signal
import sys
import argparse
from backend.mutiny import Mutiny
from backend.menu_functions import print_warning, print_error, print_success

# Path to Radamsa binary
# FIXME: add to mutiny config
RADAMSA = os.path.abspath( os.path.join(__file__, '../radamsa-0.6/bin/radamsa') )
DEBUG = False

# Set up signal handler for CTRL+C
def sigint_handler(signal: int, frame: object):
    # Quit on ctrl-c
    print_warning('\nSIGINT received, stopping\n')
    sys.exit(0)

    
def parse_arguments():
    #TODO: add description/license/ascii art print out??
    desc =  '======== The Mutiny Fuzzing Framework ==========' 
    epi = '==' * 24 + '\n'
    parser = argparse.ArgumentParser(description=desc,epilog=epi)
    parser.add_argument('prepped_fuzz', help='Path to file.fuzzer')
    parser.add_argument('target_host', help='Target to fuzz - hostname/ip address (typical) or outbound interface name (L2raw only)')

    seed_constraint = parser.add_mutually_exclusive_group()
    seed_constraint.add_argument('-r', '--range', help='Run only the specified cases. Acceptable arg formats: [ X | X- | X-Y ], for integers X,Y') 
    seed_constraint.add_argument('-l', '--loop', help='Loop/repeat the given finite number range. Acceptible arg format: [ X | X-Y | X,Y,Z-Q,R | ...]')
    seed_constraint.add_argument('-d', '--dump_raw', help='Test single seed, dump to \'dump_raw\' folder', type=int)

    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument('-q', '--quiet', help='Don\'t log the outputs', action='store_true')
    verbosity.add_argument('--log_all', help='Log all the outputs', action='store_true')

    parser.add_argument('-s', '--sleep_time', help='Time to sleep between fuzz cases (float)', type=float, default=0)
    # stub out calls to input() and related test handling
    parser.add_argument('-t', '--testing', help='For use by test suite to stub calls to input() and perform related test handling', action='store_true')

    return parser.parse_args()

if __name__ == '__main__':
    # Usage case
    if len(sys.argv) < 3:
        sys.argv.append('-h')

    args = parse_arguments()

    #Check for dependency binaries
    if not os.path.exists(RADAMSA):
        sys.exit('Could not find radamsa in %s... did you build it?' % RADAMSA)
    # set up a sigint handler only if not testing, since in testing it will be in non-main thread
    if not args.testing:
        signal.signal(signal.SIGINT, signal_handler)

    fuzzer = Mutiny(args) 
    # set the radamasa path
    fuzzer.radamsa = RADAMSA
    # set debug flag on fuzzer
    fuzzer.debug = DEBUG 
    # load any of the users custom processors
    fuzzer.import_custom_processors()
    # begin fuzzing 
    fuzzer.fuzz()

