#!/usr/bin/env python
#------------------------------------------------------------------
# Test the mutator for duplication, verify it consistently produces different results
#
# Cisco Confidential
# October 2016, created within ASIG
# Author James Spadaro (jaspadar)
#
# Copyright (c) 2014-2016 by Cisco Systems, Inc.
# All rights reserved.
#
#------------------------------------------------------------------

import signal
# Use sqlite to store generated strings
import sqlite3
import subprocess
import sys
import os

# How many iterations to run
ITERATIONS = 1000000

# Sample seed string for fuzzing
START_STRING = "GET /test1234 HTTP/1.1\r\nFrom: joebob@test.com\r\nUser-Agent: Mozilla/1.2\r\n\r\n"

# Some other defines taken from mutiny.py
RADAMSA=os.path.abspath( os.path.join(__file__, "../../../radamsa-0.3/bin/radamsa") )

# Flag to tell main execution to wrap up and exit
exit_flag = False

# Database is global for ctrl-c to write database before exit
def ctrl_c_handler(signal, frame):
    # Ensure we use the global exit_flag
    global exit_flag
    
    print("Ctrl-C received, setting exit flag...")
    exit_flag = True

signal.signal(signal.SIGINT, ctrl_c_handler)

def runFuzzer(fuzzer_input, seed):
    radamsa = subprocess.Popen([RADAMSA, "--seed", str(seed)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (fuzzer_output, error_output) = radamsa.communicate(fuzzer_input)
    if error_output:
        print(("Seed {0} Error: {1}", seed, str(error_output)))
    return fuzzer_output

def main():
    # Create database in-memory, don't retain it
    #database = sqlite3.connect(":memory:")
    # Create database on disk for later analysis
    database = sqlite3.connect("./results.db", isolation_level="IMMEDIATE")
    cursor = database.cursor()
    cursor.execute("""CREATE TABLE fuzzer_outputs (output blob, count int)""")
    cursor.execute("""CREATE TABLE seed_tracking (fuzzer_output_index int, seed int)""")
    database.commit()
    
    # How many outputs were totally unique (doesn't include any that got duped)
    originalCount = 0
    # How many strings were duped (as in if AAA appears 3 times, it will be 1 here)
    uniqueDupCount = 0
    # How many total duped outputs (as in if AAA appears 3 times, it will be 3 here)
    dupCount = 0
    
    # Ensure we use the global exit_flag
    global exit_flag
    
    for i in range(0, ITERATIONS):
        if exit_flag:
            print(("Exit flag set, exiting.  Counts at exit were {0} dup {1} original {2} uniqueDup".format(dupCount, originalCount, uniqueDupCount)))
            break
        
        # Avoid issues with non-printable characters, etc by casting as buffer
        fuzzedString = buffer(runFuzzer(START_STRING, i))
        
        # Look to see if output has already appeared
        cursor.execute("""select count from fuzzer_outputs where output=?;""", (fuzzedString,))
        result = cursor.fetchone()
        if not result:
            current_count = 1
        else:
            current_count = result[0]
            current_count += 1
        
        # Print output if duplicated
        if current_count > 1:
            cursor.execute("""update fuzzer_outputs set count=? where output=? and count=?;""", (current_count, fuzzedString, current_count-1))
            if cursor.rowcount == 0:
                import pdb
                pdb.set_trace()
            if current_count == 2:
                # First time we see a dup, count it
                uniqueDupCount += 1
                # Decrement originalCount, because there was a unique here that isn't
                originalCount -= 1
                # Bump dupCount by two, as we've seen the string twice in this case
                dupCount += 2
            else:
                # Otherwise, just bump dupCount so we can track that this repeated
                dupCount += 1
            
            # Can't use lastrowid for this, because that's only populated on insert
            cursor.execute("""select rowid from fuzzer_outputs where output=?;""", (fuzzedString,))
            cursor.execute("""insert into seed_tracking values (?, ?);""", (cursor.fetchone()[0], i))
        else:
            cursor.execute("""insert into fuzzer_outputs values (?, ?);""", (fuzzedString, current_count))
            cursor.execute("""insert into seed_tracking values (?, ?);""", (cursor.lastrowid, i))
            originalCount += 1
        database.commit()
        
        if i % 1000 == 0:
            print(("Iteration {0}: {1} dups {2} originals {3} uniqueDups so far".format(i, dupCount, originalCount, uniqueDupCount)))
    
    if not exit_flag:
        print(("Run of {0} iterations complete, dumping into debugger for analysis.", ITERATIONS))
        print(("Counts at exit were {0} dup {1} original {2} uniqueDup".format(dupCount, originalCount, uniqueDupCount)))
        import pdb
        pdb.set_trace()
    else:
        print("Run exited due to Ctrl-C.  Closing database.")
    database.close()

if __name__ == "__main__":
    main()
