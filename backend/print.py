#------------------------------------------------------------------
# Some print convenience functions
#
# Cisco Confidential
# November 2014, created within ASIG
# Author James Spadaro (jaspadar)
# Contributor Lilith Wyatt (liwyatt)
#
# Copyright (c) 2014-2015 by Cisco Systems, Inc.
# All rights reserved.
#------------------------------------------------------------------

class Print:
    SUCCESS = "\033[92m"
    WARNING = "\033[93m"
    ERROR = "\033[91m"
    CLEAR = "\033[00m"

    @classmethod
    def print_success(cls, message):
        print(f'{cls.SUCCESS}{message}{cls.CLEAR}')

    @classmethod
    def print_error(cls, message):
        print(f'{cls.ERROR}{message}{cls.CLEAR}')
    
    @classmethod
    def print_warning(cls, message):
        print(f'{cls.WARNING}{message}{cls.CLEAR}')
