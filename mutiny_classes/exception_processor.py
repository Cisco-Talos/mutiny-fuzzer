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
# This file handles all custom errors that are raised
# Copy this file to your project's mutiny classes directory to
# change exception handling
# This is useful for telling Mutiny how to interpret the server
# closing a connection, and so on
#
#------------------------------------------------------------------

import errno
import socket
from mutiny_classes.mutiny_exceptions import *

class ExceptionProcessor(object):

    def __init__(self):
        pass

    # Determine how to handle a given exception
    # Raise the exceptions defined in mutiny_exceptions to cause Mutiny
    # to do different things based on what has occurred
    def processException(self, exception):
        print(str(exception))
        if isinstance(exception, socket.error):
            if exception.errno == errno.ECONNREFUSED:
                # Default to assuming this means server is crashed so we're done
                raise LogLastAndHaltException("Connection refused: Assuming we crashed the server, logging previous run and halting")
            elif "timed out" in str(exception):
                raise AbortCurrentRunException("Server closed the connection")
            else:
                if exception.errno:
                    raise AbortCurrentRunException("Unknown socket error: %d" % (exception.errno))
                else:
                    raise AbortCurrentRunException("Unknown socket error: %s" % (str(exception)))
        elif isinstance(exception, ConnectionClosedException):
            raise AbortCurrentRunException("Server closed connection: %s" % (str(exception)))
        elif exception.__class__ not in MessageProcessorExceptions.all:
            # Default to logging a crash if we don't recognize the error
            raise LogCrashException(str(exception))
