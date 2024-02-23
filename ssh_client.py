#!/usr/bin/env python3
#
# Copyright (c) 2024 Cisco and/or its affiliates.
# 
# This software is licensed to you under the terms of the Cisco Sample
# Code License, Version 1.1 (the "License"). You may obtain a copy of the
# License at
# 
#                https://developer.cisco.com/docs/licenses
# 
# All use of the material herein must be in accordance with the terms of
# the License. All rights not expressly granted by the License are
# reserved. Unless required by applicable law or agreed to separately in
# writing, software distributed under the License is distributed on an "AS
# IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied.

import paramiko
import configparser
import logging

class SSHClient:
    def __init__(self, config_file="config.ini"):
        self.ssh = None 
        self.config_file = config_file
        self.config = self.read_config()
        try:
            self.hostname = self.config.get('SSH', 'hostname')
            self.username = self.config.get('SSH', 'username')
        except  Exception as e:
            print("Error while reading config file", str(e))
            return None
        self.password = self.config.get('SSH', 'password', fallback=None)
        self.private_key = self.config.get('SSH', 'private_key', fallback=None)
        self.port = int(self.config.get('SSH', 'port', fallback=22))
        self.ssh = self.connect()

    def read_config(self):
        # Read configuration from the file
        config = configparser.ConfigParser()
        config.read(self.config_file)
        return config

    def connect(self):
        # Create an SSH client instance
        ssh = paramiko.SSHClient()

        # Automatically add the server's host key (this is equivalent to StrictHostKeyChecking=no)
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Suppress warnings about unknown hosts (this is equivalent to UserKnownHostsFile=/dev/null)
        paramiko.util.log_to_file('/dev/null')
        #paramiko.util.log_to_file('ssh_client_debug.log')
        #logging.getLogger('paramiko').setLevel(logging.DEBUG)

        try:
            # Connect to the SSH server with either key-based or password authentication
            if self.private_key:
                print("Connecting to host {} using passwordless authentication".format(self.hostname))
                # Load the private key
                private_key_obj = paramiko.RSAKey(filename=self.private_key)
                ssh.connect(self.hostname, self.port, self.username, pkey=private_key_obj)
            elif self.password:
                print("Connecting to host {} using password authentication".format(self.hostname))
                ssh.connect(self.hostname, self.port, self.username, self.password, allow_agent=False, look_for_keys=False)
            else:
                raise ValueError("Either private_key or password must be provided for SSH authentication.")

            print("Connected to host {}".format(self.hostname))

            return ssh

        except Exception as e:
            print("Failed to connect host with Error:", str(e))
            return None

    def execute_command(self, command):
        try:
            # Execute the command on the remote host 
            print("Executing Command: {}".format(command))
            stdin, stdout, stderr = self.ssh.exec_command(command)

            # Read and print the command output
            output = stdout.read().decode('utf-8')
            #print("Command Output:\n{}".format(output))

        except Exception as e:
            print("Error executing command:\n{}", str(e))
            return None

        return output

    def disconnect(self):
        # Close the SSH connection
        if self.ssh:
            self.ssh.close()
            print("Disconnected from {}".format(self.hostname))

if __name__ == "__main__":
    ssh_client = SSHClient()
    if ssh_client.ssh:
        ssh_client.disconnect()

