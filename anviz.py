"""
    anviz
    ~~~~~

    Write docs here.

    :copyright: (c) 2014 by Augusto Roccasalva
    :license: BSD, see LICENSE for more details.
"""

import socket
import struct
from datetime import datetime
from collections import namedtuple
from configparser import ConfigParser

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

# commands
CMD_GET_INFO            = 0x30
CMD_SET_INFO            = 0x31
CMD_GET_INFO_2          = 0x32
CMD_SET_INFO_2          = 0x33
CMD_GET_DATETIME        = 0x38
CMD_SET_DATETIME        = 0x39
CMD_GET_TCPIP_PARAMS    = 0x3a
CMD_SET_TCPIP_PARAMS    = 0x3b
CMD_GET_RECORD_INFO     = 0x3c
CMD_DOWNLOAD_RECORDS    = 0x40
CMD_UPLOAD_RECORDS      = 0x41
CMD_DOWNLOAD_STAFF_INFO = 0x42
CMD_UPLOAD_STAFF_INFO   = 0x43

CMD_GET_DEVICE_SN       = 0x46
CMD_SET_DEVICE_SN       = 0x47
CMD_GET_DEVICE_TYPE     = 0x48
CMD_SET_DEVICE_TYPE     = 0x49

# crc16 bits
_crc_table = (
    0x0000,0x1189,0x2312,0x329b,0x4624,0x57ad,0x6536,0x74bf,0x8c48,0x9dc1,
    0xaf5a,0xbed3,0xca6c,0xdbe5,0xe97e,0xf8f7,0x1081,0x0108,0x3393,0x221a,
    0x56a5,0x472c,0x75b7,0x643e,0x9cc9,0x8d40,0xbfdb,0xae52,0xdaed,0xcb64,
    0xf9ff,0xe876,0x2102,0x308b,0x0210,0x1399,0x6726,0x76af,0x4434,0x55bd,
    0xad4a,0xbcc3,0x8e58,0x9fd1,0xeb6e,0xfae7,0xc87c,0xd9f5,0x3183,0x200a,
    0x1291,0x0318,0x77a7,0x662e,0x54b5,0x453c,0xbdcb,0xac42,0x9ed9,0x8f50,
    0xfbef,0xea66,0xd8fd,0xc974,0x4204,0x538d,0x6116,0x709f,0x0420,0x15a9,
    0x2732,0x36bb,0xce4c,0xdfc5,0xed5e,0xfcd7,0x8868,0x99e1,0xab7a,0xbaf3,
    0x5285,0x430c,0x7197,0x601e,0x14a1,0x0528,0x37b3,0x263a,0xdecd,0xcf44,
    0xfddf,0xec56,0x98e9,0x8960,0xbbfb,0xaa72,0x6306,0x728f,0x4014,0x519d,
    0x2522,0x34ab,0x0630,0x17b9,0xef4e,0xfec7,0xcc5c,0xddd5,0xa96a,0xb8e3,
    0x8a78,0x9bf1,0x7387,0x620e,0x5095,0x411c,0x35a3,0x242a,0x16b1,0x0738,
    0xffcf,0xee46,0xdcdd,0xcd54,0xb9eb,0xa862,0x9af9,0x8b70,0x8408,0x9581,
    0xa71a,0xb693,0xc22c,0xd3a5,0xe13e,0xf0b7,0x0840,0x19c9,0x2b52,0x3adb,
    0x4e64,0x5fed,0x6d76,0x7cff,0x9489,0x8500,0xb79b,0xa612,0xd2ad,0xc324,
    0xf1bf,0xe036,0x18c1,0x0948,0x3bd3,0x2a5a,0x5ee5,0x4f6c,0x7df7,0x6c7e,
    0xa50a,0xb483,0x8618,0x9791,0xe32e,0xf2a7,0xc03c,0xd1b5,0x2942,0x38cb,
    0x0a50,0x1bd9,0x6f66,0x7eef,0x4c74,0x5dfd,0xb58b,0xa402,0x9699,0x8710,
    0xf3af,0xe226,0xd0bd,0xc134,0x39c3,0x284a,0x1ad1,0x0b58,0x7fe7,0x6e6e,
    0x5cf5,0x4d7c,0xc60c,0xd785,0xe51e,0xf497,0x8028,0x91a1,0xa33a,0xb2b3,
    0x4a44,0x5bcd,0x6956,0x78df,0x0c60,0x1de9,0x2f72,0x3efb,0xd68d,0xc704,
    0xf59f,0xe416,0x90a9,0x8120,0xb3bb,0xa232,0x5ac5,0x4b4c,0x79d7,0x685e,
    0x1ce1,0x0d68,0x3ff3,0x2e7a,0xe70e,0xf687,0xc41c,0xd595,0xa12a,0xb0a3,
    0x8238,0x93b1,0x6b46,0x7acf,0x4854,0x59dd,0x2d62,0x3ceb,0x0e70,0x1ff9,
    0xf78f,0xe606,0xd49d,0xc514,0xb1ab,0xa022,0x92b9,0x8330,0x7bc7,0x6a4e,
    0x58d5,0x495c,0x3de3,0x2c6a,0x1ef1,0x0f78
)

def crc16(data):
    crc = 0xffff
    for b in data:
        crc = crc ^ b
        crc = (crc >> 8) ^ _crc_table[crc & 0xff]
    return struct.pack("<H", crc)


def build_request(device_id, cmd, data=b''):
    req = bytearray([STX])
    req.extend(struct.pack(">L", device_id))
    req.append(cmd)
    req.extend(struct.pack(">H", len(data)))
    if data:
        req.extend(data)
    req.extend(crc16(req))
    return req

def check_response(device_id, cmd, resp):
    dev_id, ack, ret = struct.unpack(">xLcc", resp)
    return (resp[0] == STX and\
            dev_id == device_id and\
            ack == bytes([cmd + ACK_sum]) and\
            ord(ret) == RET_SUCCESS)


NetParams = namedtuple("NetParams", "ip netmask mac gw server far com mode dhcp")
RecordsInfo = namedtuple("RecordsInfo", "users fingerprints passwords cards all_records new_records")


class DeviceException(Exception):
    pass


class Device(object):

    _connected = False

    def __init__(self):
        c = ConfigParser()
        c.read('anviz.ini')
        self.device_id = c.getint('anviz', 'device_id')
        self.ip_addr = c.get('anviz', 'ip_addr')
        self.ip_port = c.getint('anviz', 'ip_port')
        self._s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def check_connected(self):
        if not self._connected:
            self._s.connect((self.ip_addr, self.ip_port))
            self._connected = True

    def _get_response(self, cmd, args=[]):
        req = build_request(self.device_id, cmd, args)
        self.check_connected()
        self._s.send(req)
        res = bytearray(self._s.recv(7))
        if not check_response(self.device_id, cmd, res):
            raise DeviceException("Error in response")
        rlen = self._s.recv(2)
        res.extend(rlen)
        data_len = struct.unpack(">H", rlen)[0]
        data = self._s.recv(data_len)
        res.extend(data)
        crc = self._s.recv(2)
        if crc16(res) != crc:
            raise DeviceException("Checksum error")
        return data

    def get_information(self):
        data = self._get_response(CMD_GET_INFO)
        return data

    def get_datetime(self):
        data = self._get_response(CMD_GET_DATETIME)
        y, m, d, h, mi, s = struct.unpack("B"*6, data)
        return datetime(2000+y, m, d, h, mi, s)

    def set_datetime(self, dt):
        assert isinstance(dt, datetime), "You must provide datetime argument"
        args = [dt.year-2000, dt.month, dt.day, dt.hour, dt.minute, dt.second]
        res = self._get_response(CMD_SET_DATETIME, args)
        return len(res) == 0


    def get_net_params(self):
        data = self._get_response(CMD_GET_TCPIP_PARAMS)
        ip = ".".join([str(i) for i in struct.unpack("B"*4, data[0:4])])
        netmask = ".".join([str(i) for i in struct.unpack("B"*4, data[4:8])])
        mac = ":".join([format(i, "02x") for i in struct.unpack("B"*6, data[8:14])])
        gw = ".".join([str(i) for i in struct.unpack("B"*4, data[14:18])])
        server = ".".join([str(i) for i in struct.unpack("B"*4, data[18:22])])
        com = struct.unpack("H", data[23:25])[0]
        return NetParams(ip, netmask, mac, gw, server, data[22], com,
                         data[25], data[26])

    def get_record_info(self):
        data = self._get_response(CMD_GET_RECORD_INFO)
        users = sum(struct.unpack(">BH", data[:3]))
        fp = sum(struct.unpack(">BH", data[3:6]))
        passwd = sum(struct.unpack(">BH", data[6:9]))
        card = sum(struct.unpack(">BH", data[9:12]))
        all_records = sum(struct.unpack(">BH", data[12:15]))
        new_records = sum(struct.unpack(">BH", data[15:18]))
        return RecordsInfo(users, fp, passwd, card, all_records, new_records)


if __name__ == '__main__':
    clock = Device()
