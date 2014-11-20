# -*- coding: utf-8 -*-

import socket
from lib import build_request

DEFAULT_PORT = 5010

CMD_GET_INFO = 0x32
CMD_GET_DATETIME = 0x38

class Command(object):
    pass

class Connection(object):

    def __init__(self, device_id, ip, port=DEFAULT_PORT):
        self.dev_id = device_id
        self._s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._s.connect((ip, port))

    def send_cmd(self, cmd):
        req = build_request(self.dev_id, cmd)
        self._s.send(req)
        return self._s.recv(26)
