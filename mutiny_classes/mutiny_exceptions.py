#!/usr/bin/env python2
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
# This file has the custom exceptions that can be raised during fuzzing
#------------------------------------------------------------------

# Raise this to log and continue on
class LogCrashException(Exception):
    pass

# Raise this to indicate the current test shouldn't continue, skip to next
class AbortCurrentRunException(Exception):
    pass

# Raise this to indicate that the current test should be re-run
# (Same as AbortCurrentRun, but will re-try current test)
class RetryCurrentRunException(Exception):
    pass

# Raise this to log, just like LogCrashException, except 
# stop testing entirely afterwards
class LogAndHaltException(Exception):
    pass

# Raise this to log the previous run and stop testing completely
# Primarily used if daemon gives connection refused
# Assumes that previous run caused a crash
class LogLastAndHaltException(Exception):
    pass

# Raise this to simply abort testing altogether
class HaltException(Exception):
    pass

# For fuzzing campaigns, where we want to log, sleep, and continue
class LogSleepGoException(Exception):
    pass


# List of exceptions that can be thrown by a MessageProcessor
class MessageProcessorExceptions(object):
    all = [LogCrashException, AbortCurrentRunException, RetryCurrentRunException, LogAndHaltException, LogLastAndHaltException, HaltException, LogSleepGoException]

# This is raised by the fuzzer when the server has closed the connection gracefully
class ConnectionClosedException(Exception):
    pass

