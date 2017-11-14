"""Networking utility functions."""

## BEGIN Imports. ##############################################################

import pickle
import os
import socket

## END Imports. ################################################################

def determine_host_address():
    """Determines the human-readable host address of the local machine. 
    First checks if environment variable DISTKERAS_HOSTNAME is set, and 
    if so uses this as host name. Otherwise, checks using socket"""
    host_env_var = 'DISTKERAS_HOSTNAME'
    host_address = os.environ.get(host_env_var, socket.gethostbyname(socket.gethostname()))
    return host_address

def determine_port():
    """Determines port to connect to on local machine. 
    First checks if environment variable DISTKERAS_PORT is set, and 
    if so uses this as port. Otherwise, assign to a default"""
    port_env_var = 'DISTKERAS_PORT'
    port = int(os.environ.get(port_env_var, 5000))
    return port

def recvall(connection, num_bytes):
    """Reads `num_bytes` bytes from the specified connection.

    # Arguments
        connection: socket. Opened socket.
        num_bytes: int. Number of bytes to read.
    """
    byte_buffer = b''
    buffer_size = 0
    bytes_left = num_bytes
    # Iterate until we received all data.
    while buffer_size < num_bytes:
        # Fetch the next frame from the network.
        data = connection.recv(bytes_left)
        # Compute the size of the frame.
        delta = len(data)
        buffer_size += delta
        bytes_left -= delta
        # Append the data to the buffer.
        byte_buffer += data

    return byte_buffer


def recv_data(connection):
    """Will fetch the next data frame from the connection.

    The protocol for reading is structured as follows:
    1. The first 20 bytes represents a string which holds the next number of bytes to read.
    2. We convert the 20 byte string to an integer (e.g. '00000000000000000011' -> 11).
    3. We read `num_bytes` from the socket (which is in our example 11).
    4. Deserialize the retrieved string.

    # Arguments
        connection: socket. Opened socket.
    """
    data = b''
    # Fetch the serialized data length.
    length = int(recvall(connection, 20).decode())
    # Fetch the serialized data.
    serialized_data = recvall(connection, length)
    # Deserialize the data.
    data = pickle.loads(serialized_data)

    return data


def send_data(connection, data):
    """Sends the data to the other endpoint of the socket using our protocol.

    The protocol for sending is structured as follows:
    1. Serialize the data.
    2. Obtain the buffer-size of the serialized data.
    3. Serialize the buffer-size in 20 bytes (e.g. 11 -> '00000000000000000011').
    4. Send the serialized buffer size.
    5. Send the serialized data.

    # Arguments
        connection: socket. Opened socket.
        data: any. Data to send.
    """
    # Serialize the data.
    serialized_data = pickle.dumps(data, -1)
    length = len(serialized_data)
    # Serialize the number of bytes in the data.
    serialized_length = str(length).zfill(20)
    # Send the data over the provided socket.
    connection.sendall(serialized_length.encode())
    connection.sendall(serialized_data)


def connect(host, port, disable_nagle=True):
    fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Check if Nagle's algorithm needs to be disabled.
    if disable_nagle:
        fd.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    else:
        fd.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
    # Connect to the specified URI.
    fd.connect((host, port))

    return fd
