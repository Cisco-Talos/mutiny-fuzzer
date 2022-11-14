import dis
import queue
import time
import unittest
from backend.proc_director import ProcDirector
from mutiny_classes.mutiny_exceptions import *
from mutiny_classes import monitor

class TestMonitorWrapper(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    # This monitor will immediately "Crash"
    class MonitorCrash(object):
        is_enabled = True
        def monitor_target(self, target_ip, target_port, signal_main):
            exception = LogCrashException('Information about the crash')
            exception.extra_data = 'Can add arbitrary members'
            signal_main(exception)

    # This monitor will sleep for 1 second, then "crash"
    class Monitor1SecDelayCrash(object):
        is_enabled = True
        def monitor_target(self, target_ip, target_port, signal_main):
            time.sleep(1)
            exception = LogCrashException('Information about the crash')
            exception.extra_data = 'Can add arbitrary members'
            signal_main(exception)

    # This monitor raises SignalMain without an exception
    class MonitorNonException(object):
        is_enabled = True
        def monitor_target(self, target_ip, target_port, signal_main):
            signal_main('This should fail, requires an exception, not a string')

    # This monitor doesn't have is_enabled defined
    class MonitorNoIsEnabled(object):
        def monitor_target(self, target_ip, target_port, signal_main):
            pass

    # Test the default monitor bundled with Mutiny - should not crash
    def test_default_monitor(self):
        wrapper = ProcDirector.MonitorWrapper('127.0.0.1', 2500, monitor.Monitor())
        self.assertTrue(wrapper.queue.empty())
        
    # Test a monitor that sends "crash" immediately
    def test_crash_monitor(self):
        wrapper = ProcDirector.MonitorWrapper('127.0.0.1', 2500, self.MonitorCrash())
        time.sleep(0.1)
        self.assertFalse(wrapper.queue.empty())
        self.assertTrue(type(wrapper.queue.get()), LogCrashException)
    
    # Test a monitor that sends "crash" after 1 second
    def test_1sec_delay_crash_monitor(self):
        wrapper = ProcDirector.MonitorWrapper('127.0.0.1', 2500, self.Monitor1SecDelayCrash())
        self.assertTrue(wrapper.queue.empty())
        time.sleep(1.1) # Give a bit of breathing room
        self.assertFalse(wrapper.queue.empty())
        self.assertTrue(type(wrapper.queue.get()), LogCrashException)

    # Test sending a non-exception to signal_main()
    def test_non_exception(self):
        wrapper = ProcDirector.MonitorWrapper('127.0.0.1', 2500, self.MonitorNonException())
        time.sleep(0.1)
        self.assertFalse(wrapper.queue.empty())
        self.assertTrue(type(wrapper.queue.get()), HaltException)
        
    # Test a monitor without is_enabled member
    def test_no_is_enabled(self):
        with self.assertRaises(SystemExit) as context_manager:
            wrapper = ProcDirector.MonitorWrapper('127.0.0.1', 2500, self.MonitorNoIsEnabled())
