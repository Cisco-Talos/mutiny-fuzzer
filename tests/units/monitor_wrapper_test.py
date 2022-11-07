import dis
import queue
import time
import unittest
from backend.proc_director import ProcDirector
from mutiny_classes.mutiny_exceptions import *
from mutiny_classes import monitor

class TestMonitorWrapper(unittest.TestCase):
    # This monitor will immediately "Crash"
    class MonitorCrash(object):
        is_enabled = True
        def monitorTarget(self, targetIP, targetPort, signalMain):
            exception = LogCrashException('Information about the crash')
            exception.extra_data = 'Can add arbitrary members'
            signalMain(exception)

    # This monitor will sleep for 1 second, then "crash"
    class Monitor1SecDelayCrash(object):
        is_enabled = True
        def monitorTarget(self, targetIP, targetPort, signalMain):
            time.sleep(1)
            exception = LogCrashException('Information about the crash')
            exception.extra_data = 'Can add arbitrary members'
            signalMain(exception)

    def setUp(self):
        pass

    def tearDown(self):
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

    # Test sending a non-exception to signalMain()
    def test_non_exception(self):
        # Use default monitor so it doesn't actually do anything
        wrapper = ProcDirector.MonitorWrapper('127.0.0.1', 2500, monitor.Monitor())
        with self.assertRaises(SystemExit) as context_manager:
            # Manually invoke signalMain() this way because otherwise didn't see how to detect SystemExit
            # If we give a monitor that does signalMain(string), the child thread will do sys.exit(-1)
            wrapper.signalCrashDetectedOnMain('this should fail, as it is not an exception')
        self.assertEqual(context_manager.exception.code, -1)
        
