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
# This file finds and imports any custom exception_processor.py, 
# message_processor.py, or monitor.py files specified by the 
# processor_dir parameter passed in the .fuzzer file generated
# by the mutiny_prep.py file.
# It also spawns any Monitors in a parallel thread
#
#------------------------------------------------------------------

import imp
import sys
import os.path
import threading
import socket

from os import listdir
from threading import Event
from mutiny_classes.mutiny_exceptions import MessageProcessorExceptions

class ProcDirector(object):
    def __init__(self, processDir):
        self.messageProcessor = None
        self.exceptionProcessor = None
        self.exceptionList = None
        self.monitor = None
        mod_name = ""  
        self.classDir = "mutiny_classes"
        
        defaultDir = os.path.join(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.pardir),self.classDir)
        filelist = [ "exception_processor","message_processor","monitor" ]
        
        # Load all processors, attempting to do custom first then default
        for filename in filelist:
            try:
                # Attempt to load custom processor
                filepath = os.path.join(processDir, "{0}.py".format(filename))
                imp.load_source(filename, filepath)
                print(("Loaded custom processor: {0}".format(filepath)))
            except IOError:
                # On failure, load default
                filepath = os.path.join(defaultDir, "{0}.py".format(filename))
                imp.load_source(filename, filepath)
                print(("Loaded default processor: {0}".format(filepath)))
                
        # Set all the appropriate classes to the appropriate modules
        self.messageProcessor = sys.modules['message_processor'].MessageProcessor
        self.exceptionProcessor = sys.modules['exception_processor'].ExceptionProcessor
        self.monitor = sys.modules['monitor'].Monitor 
        self.crashQueue = Event()
    
    class MonitorWrapper(object):
        def __init__(self, targetIP, targetPort, monitor):
            # crashDetectedEvent signals main thread on a detected crash,
            # interrupt_main() and CTRL+C, otherwise raise the same signal
            # monitor is the actual user custom monitor that implements monitorTarget
            self.monitor = monitor
            self.crashEvent = threading.Event()
            self.task = threading.Thread(target=self.monitor.monitorTarget,args=(targetIP,targetPort,self.signalCrashDetectedOnMain))
            self.task.daemon = True
            self.task.start()

        # Don't override this function
        def signalCrashDetectedOnMain(self):
            # Raises a KeyboardInterrupt exception on main thread
            self.crashEvent.set()
            # Ugly but have to import here for this to work in monitorTarget on a custom processor
            import _thread
            _thread.interrupt_main()
    
    def startMonitor(self, host, port):
        self.monitorWrapper = self.MonitorWrapper(host, port, self.monitor())
        return self.monitorWrapper
        
