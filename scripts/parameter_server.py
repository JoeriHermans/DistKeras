"""Helper script which initiates a parameter server session."""

## BEGIN Imports. ##############################################################

from distkeras.networking import connect
from distkeras.networking import recv_data
from distkeras.networking import send_data
from distkeras.networking import allocate_tcp_listening_port
from distkeras.networking import determine_host_address

from distkeras.utils import serialize_keras_model
from distkeras.utils import deserialize_keras_model

from distkeras.native.parameter_servers import ParameterServer

import optparse

import os

import socket

import threading

## END Imports. ################################################################

def parse_arguments():
    parser = optparse.OptionParser()
    parser.set_defaults(control_port=0, worker_port=0, identifier=None)
    parser.add_option('--control-port', action='store', dest='control_port', type='int')
    parser.add_option('--worker-port', action='store', dest='worker_port', type='int')
    parser.add_option('--identifier', action='store', dest='identifier', type='int')
    (options, args) = parser.parse_args()

    return options

def allocate_parameter_server(fd, port, model, parameters, identifier):
    ps = ParameterServer(identifier, fd, port, model, parameters)
    ps.start()

    return ps

def main():
    # Parse the program arguments.
    options = parse_arguments()
    # Allocate socket resources.
    fd_control, port_control = allocate_tcp_listening_port(port=options.control_port)
    fd_worker, port_worker = allocate_tcp_listening_port(port=options.worker_port)
    # Handle control connections.
    conn, addr = fd_control.accept()
    # Obtain parameterization, and the model from the job.
    data = recv_data(conn)
    model = deserialize_keras_model(data['model'])
    parameters = data['parameters']
    identifier = options.identifier
    # Allocate the parameter server.
    ps = allocate_parameter_server(fd_worker, port_worker, model, parameters, identifier)
    # Wait for the job to send the stop signal.
    data = recv_data(conn)
    if data['stop']:
        ps.stop()
    # Wait for the parameter server to shut down.
    ps.join()
    # Close the control connection.
    conn.close()
    # Close socket resources.
    fd_control.close()
    fd_worker.close()

if __name__ == '__main__':
    main()
