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

import os
import json
import paramiko
import random
from datetime import datetime
from ssh_client import SSHClient 
sudi_cert_output_path = "output/"

class CiscoPlatformSecurity:
    def __init__(self):
        self.nonce = self.GenerateNonceHexString(8)
        self.cli_sudi_cert = "show platform security attest certificate CiscoSUDI location all nonce " + str(self.nonce) + " json "
        self.ssh_client = SSHClient()
        if self.ssh_client.ssh:
            self.sudi_cert_output_file = self._GenerateOutputFileName()
            self.read_SUDI_cert = self.ReadSUDIcert()
        else:
            raise RuntimeError

    def GenerateNonceHexString(self, length):
        hex_char = "0123456789abcdef"
        nonce_hex = ''.join(random.choice(hex_char) for _ in range(length))
        return nonce_hex

    def GetNonce(self):
        return self.nonce

    def GetOutputFileName(self):
        return self.sudi_cert_output_file

    def _GenerateOutputFileName(self):
        # Create output directory if not available
        if not os.path.exists(sudi_cert_output_path):
            os.makedirs(sudi_cert_output_path)
        # Get the current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        # Create the filename with the timestamp
        filename = "sudi_certs_{}.json".format(timestamp)
        return os.path.join(sudi_cert_output_path, filename)

    def ReadSUDIcert(self):
        if self.ssh_client.ssh:
            sudi_cert_json_output = self.ssh_client.execute_command(self.cli_sudi_cert)
            #print("CiscoSUDI raw JSON output:", sudi_cert_json_output)
            #parse CLI output and save into JSON file
            try:
                sudi_cert_parsed_json = json.loads(sudi_cert_json_output.strip())
            except:
                sudi_cert_json_output = sudi_cert_json_output.partition("{")
                jsondata = str(sudi_cert_json_output[1]) + str(sudi_cert_json_output[2])
                sudi_cert_parsed_json = json.loads(jsondata)
                del jsondata 
               
                # Save the JSON output to a file
                with open(self.sudi_cert_output_file, 'w') as json_file:
                    json.dump(sudi_cert_parsed_json, json_file, indent=4)

                print("CiscoSUDI JSON output saved to '{}'".format(self.sudi_cert_output_file))
            self.ssh_client.disconnect()



if __name__ == "__main__":
    Platform_Security = CiscoPlatformSecurity()
