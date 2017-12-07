#!/usr/bin/env python
#------------------------------------------------------------------
#
# Cisco Confidential
# November 2014, created within ASIG
# Author James Spadaro (jaspadar)
# Contributor Lilith Wyatt (liwyatt)
#
# Copyright (c) 2014-2015 by Cisco Systems, Inc.
# All rights reserved.
#
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

# List of exceptions that can be thrown by a MessageProcessor
class MessageProcessorExceptions(object):
    all = [LogCrashException, AbortCurrentRunException, RetryCurrentRunException, LogAndHaltException, LogLastAndHaltException, HaltException]

# This is raised by the fuzzer when the server has closed the connection gracefully
class ConnectionClosedException(Exception):
    pass

