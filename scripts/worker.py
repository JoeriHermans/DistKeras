"""Helper script which initiates a worker from a dist-keras ML daemon."""

## BEGIN Imports. ##############################################################

from distkeras.networking import connect
from distkeras.networking import recv_data
from distkeras.networking import send_data
from distkeras.networking import allocate_tcp_listening_port

from distkeras.native.workers import Worker

import optparse

import os

import socket

import threading

## END Imports. ################################################################

def parse_arguments():
    parser = optparse.OptionParser()
    parser.set_defaults(control_port=0, identifier=None)
    parser.add_option('--control-port', action='store', dest='control_port', type='int')
    parser.add_option('--identifier', action='store', dest='identifier', type='int')
    (options, args) = parser.parse_args()

    return options

def allocate_worker(identifier, data):
    w = Worker()
    w.set_parameters(data['parameters'])
    w.set_parameter_servers(data['parameter_servers'])
    w.set_model(data['model'])

    return w

def main():
    # Parse the program arguments.
    options = parse_arguments()
    # Allocate socket resources.
    fd, port = allocate_tcp_listening_port(port=options.control_port)
    # Handle control connections.
    conn, addr = fd.accept()
    # Obtain the parameterization, and the model from the job.
    data = recv_data(conn)
    # Allocate the worker.
    worker = allocate_worker(options.identifier, data)
    # Send that the worker is ready for training.
    send_data(conn, {'status': True})
    # Wait for the starting signal.
    data = recv_data(conn)
    if data['start']:
        worker.start()
    # Wait for the worker to finish the training procedure.
    worker.join()
    # Send the finished signal.
    send_data(conn, {'done': True})
    conn.close()
    fd.close()

if __name__ == '__main__':
    main()
