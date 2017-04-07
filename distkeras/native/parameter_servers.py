"""Native Parameter Servers

Module which handles the parameter server routines.
"""

## BEGIN Imports. ##############################################################

from distkeras.networking import allocate_tcp_listening_port
from distkeras.networking import recv_data
from distkeras.networking import send_data

from distkeras.utils import deserialize_keras_model

import numpy as np

import threading

import os

## END Imports. ################################################################

class ParameterServer(threading.Thread):

    def __init__(self, identifier, listening_socket, port, model, parameters):
        threading.Thread.__init__(self)
        # Initialize default parameter server
        self.parameters = parameters
        self.identifier = identifier
        self.socket = listening_socket
        self.port = port
        self.weights = {}
        self.weight_identifiers = []
        self.locks = {}
        self.connections = []
        self.running = False
        self.model = model

    def setup_parameter_server(self):
        # Fetch the weights of the models.
        weights = np.asarray(self.model.get_weights())
        # Fetch the weight allocations.
        weight_allocations = self.parameters['weight_allocations'][self.identifier]
        # Set the weight allocations.
        for index in weight_allocations:
            w = weights[index]
            self.weight_identifiers.append(index)
            self.locks[index] = threading.Lock()
            self.weights[index] = w

    def initialize(self):
        self.running = True

    def start(self):
        self.initialize()
        super(ParameterServer, self).start()

    def run(self):
        # Setup the weight matrixes based on the parameters.
        self.setup_parameter_server()
        while self.running:
            try:
                conn, addr = self.socket.accept()
                thread = threading.Thread(target=self.handle_connection, args=(conn,))
                thread.start()
                self.connections.append(thread)
            except:
                pass

    def stop(self):
        self.running = False
        if self.socket:
            self.cleanup_connections()
            self.socket.close()
            self.cancel_accept()
            self.socket = None
        self.connections = []

    def handle_commit(self, fd):
        data = recv_data(fd)
        for i in self.weight_identifiers:
            with self.locks[i]:
                self.weights[i] = np.add(self.weights[i], data[i])

    def handle_pull(self, fd):
        data = {}
        for i in self.weight_identifiers:
            with self.locks[i]:
                data[i] = self.weight[i].copy()
        send_data(fd, data)

    def handle_connection(self, fd):
        try:
            # Handling socket
            while self.running:
                action = fd.recv(1).decode()
                if action == 'c':
                    self.handle_commit(fd)
                elif action == 'p':
                    self.handle_pull(fd)
                else:
                    break
            # Close the socket.
            fd.close()
        except Exception as e:
            print(e)

    def cancel_accept(self):
        try:
            fd = connect('localhost', self.port)
            fd.close()
        except:
            pass

    def cleanup_connections(self):
        for thread in self.connections:
            thread.join()
            del thread
