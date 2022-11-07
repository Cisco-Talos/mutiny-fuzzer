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
import queue
import os
import signal
import socket
import threading
import traceback

from threading import Event
from mutiny_classes.mutiny_exceptions import MessageProcessorExceptions, HaltException
from backend.menu_functions import print_success, print_error, print_warning

class ProcDirector(object):
    def __init__(self, processDir):
        self.messageProcessor = None
        self.exceptionProcessor = None
        self.exceptionList = None
        self.monitor = None
        mod_name = ""  
        self.classDir = "mutiny_classes"
        self.is_monitor_used = False
        
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
            # This queue is read from the main thread after each fuzz run
            # If it contains an exception, that is passed to the exception processor
            self.queue = queue.SimpleQueue()
            # monitor is the actual user custom monitor that implements monitorTarget
            self.monitor = monitor
            
            if not hasattr(self.monitor, 'is_enabled'):
                print_error('Mutiny updates added a Monitor "is_enabled" member.  This lets Mutiny detect and better handle problems with a Monitor.')
                print_error('It is missing from your Monitor, please reference mutiny_classes/monitor.py and add it.')
                sys.exit(-1)
            
            # Immediately start monitor and allow it to run until Mutiny stops if enabled
            if self.monitor.is_enabled:
                self.task = threading.Thread(target=self.monitorTarget,args=(self.monitor.monitorTarget, targetIP,targetPort,self.signalCrashDetectedOnMain))
                # Daemon thread won't stop main thread from exiting
                self.task.daemon = True
                self.task.start()
            else:
                print('Monitor disabled')
        
        # Wrap Monitor's monitorTarget *inside* of thread so we can do exception handling
        def monitorTarget(self, monitor, *args):
            try:
                monitor(*args)
                # Really shouldn't reach this
                print_warning('Halting Mutiny - Monitor stopped (no errors) but it should run indefinitely.')
                
                # Can't sys.exit() inside thread:
                self.queue.put(HaltException('Monitor stopped.'))
            except Exception as e:
                # Catch if Monitor dies and halt Mutiny
                print_error('\nHalting Mutiny - Received exception from Monitor, backtrace:\n')
                traceback.print_exc()
                print('', flush=True)
                # Can't sys.exit() inside thread:
                self.queue.put(HaltException('Monitor threw an exception.'))

        # Don't override this function
        def signalCrashDetectedOnMain(self, exception: Exception):
            if not isinstance(exception, Exception):
                print_error('Invalid monitor behavior - signalMain() must be sent an exception, usually a Mutiny exception.')
                print(f'Received: {str(exception)}')
                # Can't sys.exit() inside thread:
                os.kill(os.getpid(), signal.SIGINT)
            self.queue.put(exception)
    
    def startMonitor(self, host, port):
        self.monitorWrapper = self.MonitorWrapper(host, port, self.monitor())
        return self.monitorWrapper
    
    def checkMonitor(self):
        pass
        
        
