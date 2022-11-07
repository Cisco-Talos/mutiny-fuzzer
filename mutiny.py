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
#
#------------------------------------------------------------------



# Path to Radamsa binary
RADAMSA=os.path.abspath( os.path.join(__file__, "../radamsa/bin/radamsa") )
# Whether to print debug info
DEBUG_MODE=False
# For dumpraw option, dump into log directory by default, else 'dumpraw'
DUMPDIR = ""

MONITOR = None




def parseFuzzArgs(parser):
    '''
    parse arguments for fuzzing
    '''
    parser.add_argument("prepped_fuzz", help="Path to file.fuzzer")
    parser.add_argument("target_host", help="Target to fuzz - hostname/ip address (typical) or outbound interface name (L2raw only)")
    parser.add_argument("-s", "--sleeptime", help="Time to sleep between fuzz cases (float)", type=float, default=0)

    seed_constraint = parser.add_mutually_exclusive_group()
    seed_constraint.add_argument("-r", "--range", help="Run only the specified cases. Acceptable arg formats: [ X | X- | X-Y ], for integers X,Y") 
    seed_constraint.add_argument("-l", "--loop", help="Loop/repeat the given finite number range. Acceptible arg format: [ X | X-Y | X,Y,Z-Q,R | ...]")
    seed_constraint.add_argument("-d", "--dumpraw", help="Test single seed, dump to 'dumpraw' folder", type=int)

    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("-q", "--quiet", help="Don't log the outputs", action="store_true")
    verbosity.add_argument("--logAll", help="Log all the outputs", action="store_true")
    parser.set_defaults(func=fuzz)

def parsePrepArgs(parser):
    '''
    parse arguments for fuzzer file preparation
    '''
    parser.add_argument("pcap_file", help="Pcap/c_array output from wireshark")
    parser.add_argument("-d","--processor_dir", help = "Location of custom pcap Message/exception/log/monitor processors if any, see appropriate *processor.py source in ./mutiny_classes/ for implementation details", nargs=1, default=["default"])
    parser.add_argument("-a", "--dump_ascii", help="Dump the ascii output from packets ", action="store_true", default=False)
    parser.add_argument("-f", "--force", help="Take all default options", action = "store_true", default=False) 
    parser.add_argument("-r", "--raw", help="Pull all layer 2+ data / create .fuzzer for raw sockets", action = "store_true", default=False) 
    parser.set_defaults(func=prep)
    
def parseArguments():
    #TODO: add description/license/ascii art print out??
    # FIXME: let fuzz run by default and prep indiciate a subcommand
    desc =  "======== The Mutiny Fuzzing Framework ==========" 
    epi = "==" * 24 + '\n'
    parser = argparse.ArgumentParser(description=desc,epilog=epi)

    subparsers = parser.add_subparsers(title='subcommands')
    prepParser = subparsers.add_parser('prep', help='convert a pcap/c_array output into a .fuzzer file') 
    fuzzParser = subparsers.add_parser('fuzz', help='begin fuzzing using a .fuzzer file')

    parsePrepArgs(prepParser)
    parseFuzzArgs(fuzzParser)

    return parser.parse_args()

if __name__ == '__main__':
    # Usage case
    if len(sys.argv) < 3:
        sys.argv.append('-h')

    #Check for dependency binaries
    if not os.path.exists(RADAMSA):
        sys.exit("Could not find radamsa in %s... did you build it?" % RADAMSA)

    args = parseArguments()

    args.func(args)
    if 'prep'in args:
        # fuzzer_prep = Mutiny_prep(args)
        
    else:
        #fuzzer = Mutiny(args) 
        # fuzzer.import_custom_processors()
        # fuzzer.fuzz()
        
