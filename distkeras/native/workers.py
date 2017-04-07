"""Native workers module.

Specific distributed optimizer implementations.
"""

## BEGIN Imports. ##############################################################

from distkeras.networking import allocate_tcp_listening_port
from distkeras.networking import connect
from distkeras.networking import recv_data
from distkeras.networking import send_data

import tensorflow as tf

from keras import backend as K

from distkeras.utils import deserialize_keras_model

import numpy as np

import socket

import threading

import os

## END Imports. ################################################################

class Worker(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.center_variable = None
        self.identifier = None
        self.loss = None
        self.model = None
        self.num_epochs = None
        self.parameter_servers = []
        self.parameters = None
        self.ps_sockets = []
        self.running = False
        self.worker_optimizer = None
        self.batch_size = None

    def set_parameters(self, parameters):
        self.parameters = parameters
        self.batch_size = parameters['batch_size']
        self.communication_frequency = parameters['communication_frequency']
        self.identifier = parameters['worker_identifier']
        self.loss = parameters['loss']
        self.num_epochs = parameters['num_epochs']
        self.worker_optimizer = parameters['worker_optimizer']

    def set_parameter_servers(self, parameter_servers):
        # Store the list of parameter servers
        self.parameter_servers = parameter_servers
        # Connect to the given parameter servers.
        for ps in self.parameter_servers:
            fd = connect(ps[0], ps[1])
            self.ps_sockets.append(fd)

    def set_model(self, model):
        self.model = model

    def start(self):
        self.running = True
        super(Worker, self).start()

    def compile_model(self):
        self.model = deserialize_keras_model(self.model)
        self.model.compile(loss=self.loss,
                           optimizer=self.worker_optimizer,
                           metrics=['accuracy'])

    def stop(self):
        self.running = False

    def commit(self, delta):
        # TODO Implement.
        print("Committing")

    def pull(self):
        # TODO Implement.
        print("Pulling")

    def disconnect_parameter_servers(self):
        for socket in self.ps_sockets:
            socket.sendall('s')
            socket.close()

    def run(self):
        # Compile the current Keras model.
        self.compile_model()
        # Get the most recent central variable.
        self.pull()
        # Start the training procedure.
        while self.running:
            # TODO Implement.
            import time
            time.sleep(10)
            self.running = False
        # Close connection with the remote parameter servers.
        self.disconnect_parameter_servers()
        print("Worker done")
