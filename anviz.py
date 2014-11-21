"""
    anviz
    ~~~~~

    Write docs here.

    :copyright: (c) 2014 by Augusto Roccasalva
    :license: BSD, see LICENSE for more details.
"""

import struct

# some constants
STX = 0xa5
ACK_sum = 0x80

# return value constants
RET_SUCCESS         = 0x00 # operation successful
RET_FAIL            = 0x01 # operation failed
RET_FULL            = 0x04 # user full
RET_EMPTY           = 0x05 # user empty
RET_NO_USER         = 0x06 # user not exist
RET_TIME_OUT        = 0x08 # capture timeout
RET_USER_OCCUPIED   = 0x0a # user already exists
RET_FINGER_OCCUPIED = 0x0b # fingerprint already exists
