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

import json
import argparse
import os, sys, struct
import base64
from pathlib import Path

#import OpenSSL
import binascii
import cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from read_sudi_certs import CiscoPlatformSecurity

file_path_cisco_rootCA_cert_2099     = "certs/crca2099.pem"
file_path_cisco_rootCA_cert_2048     = "certs/crca2048.pem"
file_path_cisco_subCA_cert_ACT2sudi  = "certs/ACT2SUDICA.pem"
file_path_cisco_subCA_cert_HAsudi    = "certs/hasudi.pem"

args_input_sudi_cert_file = None

class CiscoSUDI:
    def __init__(self, sudicert_file):
        # Read Cisco CA certificates from files
        self.cisco_rootCA_cert_2099 = self.ReadCertFromFile(file_path_cisco_rootCA_cert_2099)
        self.cisco_rootCA_cert_2048 = self.ReadCertFromFile(file_path_cisco_rootCA_cert_2048)
        self.cisco_subCA_cert_HAsudi   = self.ReadCertFromFile(file_path_cisco_subCA_cert_HAsudi)
        self.cisco_subCA_cert_ACT2sudi = self.ReadCertFromFile(file_path_cisco_subCA_cert_ACT2sudi)
        self.input_sudicert_file = sudicert_file
        try:
            if self.input_sudicert_file is None:
                # Read CiscoSUDI certs from device
                self.platform_security = CiscoPlatformSecurity()
                self.output_sudicert_file = self.platform_security.GetOutputFileName()
                self.load_SUDI_certs   = self.LoadSUDIcerts(filepath=self.output_sudicert_file)
            else:
                # Load and Verify the input CiscoSUDI file
                self.load_SUDI_certs   = self.LoadSUDIcerts(filepath=self.input_sudicert_file)
                self.output_sudicert_file = self.input_sudicert_file
        except Exception as e:
            sys.exit(1)
        self.verify_SUDI_certs = self.VerifySUDIcerts()
        self.SUDI_certs        = None

    def ReadCertFromFile(self, cert_file):
        file_path = Path(cert_file)
        if file_path.exists():
            try:
                with open(cert_file, 'rb') as file:
                    cert_data = file.read()
                return cert_data
            except Exception as e:
                print("\nError reading {} certificate from file: {}".format(cert_file, e))
                return None
        else:
            print("The file {} does not exist".format(cert_file))
            return None

        
    def Compare_cisco_rootCA_with_sudiRoot(self, flag_rootCA_cert_2099, sudiRoot):
        try:
            if flag_rootCA_cert_2099:
                ciscoCN = "Cisco Root CA 2099"
                cisco_rootCA_file = self.cisco_rootCA_cert_2099
            else:
                ciscoCN = "Cisco Root CA 2048"
                cisco_rootCA_file = self.cisco_rootCA_cert_2048

            # Load the cisco rootCA certificate in PEM format
            cisco_rootCA = x509.load_pem_x509_certificate(cisco_rootCA_file, default_backend())

            # Validate if its CiscoCA or not
            dict_for_subject = self.GetCertSubjectDict(cert=cisco_rootCA)
            if ciscoCN not in dict_for_subject["Common Name"]:
                print("SUDI Root Certificate{} is not a valid Cisco RootCA(CN={})".format(cisco_rootCA_file, ciscoCN))
                return False

            # Check if the cisco rootCA is same as sudiRoot certificate
            # byte representation obtained from public_bytes() is DER encoded binary format
            if cisco_rootCA.public_bytes(encoding=serialization.Encoding.DER) == sudiRoot.public_bytes(encoding=serialization.Encoding.DER):
                print("SUDI Root Certificate confirmed as Cisco RootCA(CN={})".format(ciscoCN))
                return True

            print("SUDI Root Certificate is not Cisco RootCA(CN={})".format(ciscoCN))
            # Print Certificate Info
            self.PrintCertInfo(cert=sudiRoot)
            return False

        except Exception as e:
            print("Error in confirming SUDI Root with Cisco RootCA: {}".format(e))
            return False


    def Compare_cisco_subCA_with_sudiCA(self, flag_subCA_HAsudi, sudiCA):
        try:
            if flag_subCA_HAsudi:
                ciscoCN = "High Assurance SUDI CA"
                cisco_subCA_file = self.cisco_subCA_cert_HAsudi
            else:
                ciscoCN = "ACT2 SUDI CA"
                cisco_subCA_file = self.cisco_subCA_cert_ACT2sudi

            # Load the cisco subCA certificate in PEM format
            cisco_subCA = x509.load_pem_x509_certificate(cisco_subCA_file, default_backend())

            # Validate if its CiscoCA or not
            dict_for_subject = self.GetCertSubjectDict(cert=cisco_subCA)
            if ciscoCN not in dict_for_subject["Common Name"]:
                print("SUDI CA Certificate{} is not a valid Cisco subCA(CN={})".format(cisco_subCA_file, ciscoCN))
                return False

            # Check if the cisco subCA is same as sudiCA certificate
            # byte representation obtained from public_bytes() is DER encoded binary format
            if cisco_subCA.public_bytes(encoding=serialization.Encoding.DER) == sudiCA.public_bytes(encoding=serialization.Encoding.DER):
                print("SUDI CA Certificate confirmed as Cisco subCA(CN={})".format(ciscoCN))
                return True

            print("SUDI CA Certificate is not Cisco subCA(CN={})".format(ciscoCN))
            # Print Certificate Info
            self.PrintCertInfo(cert=sudiCA)
            return False

        except Exception as e:
            print("Error in confirming SUDI CA with Cisco subCA: {}".format(e))
            return False

    def LoadSUDIcerts(self, filepath):
        if not os.path.isfile(filepath):
            print("Error, file not found: {}".format(filepath))
            sys.exit(1)

        with open(filepath, "r") as f:
            filedata = f.read()
            f.close()

        try:
            self.SUDI_certs = json.loads(filedata.strip())
        except:
            filedata = filedata.partition("{")
            jsondata = str(filedata[1]) + str(filedata[2])
            self.SUDI_certs = json.loads(jsondata)
            del jsondata

    def LoadCertificateFromDer(self, der_data):
        try:
            certificate = x509.load_der_x509_certificate(der_data, default_backend())
            # If no exception occurs, the certificate is loaded successfully
            return certificate
        except Exception as e:
            # Handle the exception here
            print("Error loading X.509 certificate: {}".format(e))
            return None

    def GetCertSubjectDict(self, cert):
        dict_for_subject = {}
        subject  = cert.subject
        # Retrieve subject attributes
        if len(subject.get_attributes_for_oid(x509.oid.NameOID.SERIAL_NUMBER))!=0 :
            dict_for_subject["SerialNumber"]=subject.get_attributes_for_oid(x509.oid.NameOID.SERIAL_NUMBER)[0].value
        if len(subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME))!=0 :
            dict_for_subject["Organization"]=subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value
        if len(subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME))!=0 :
            dict_for_subject["Organizational Unit"]=subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
        if len(subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME))!=0 :
            dict_for_subject["Common Name"]=subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value

        return dict_for_subject

    def GetCertIssuerDict(self, cert):
        dict_for_issuer = {}
        issuer   = cert.issuer
        # Retrieve issuer attributes
        if len(issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME))!=0 :
            dict_for_issuer["Common Name"]=issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        if len(issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME))!=0 :
            dict_for_issuer["Organization"]=issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value

        return dict_for_issuer

    def PrintCertInfo(self, cert):

        print("{:>{}}{}".format("", 2, "Version: {}".format(cert.version)))
        print("{:>{}}{}".format("", 2, "Serial Number: {}".format(cert.serial_number)))

        # Retrieve issuer attributes
        dict_for_issuer  = self.GetCertIssuerDict(cert=cert)
        dict_for_subject = self.GetCertSubjectDict(cert=cert)

        #Print Subject
        #Example:
        #Subject: Serial Number=PID:N540X-XXXXXXXXX- SN:XXXXXXXXXXX, O=Cisco, OU=ACT-2 Lite SUDI,
        #         Name=Cisco NCS 540 System with 16x10G+4x1GCu+8x25G+2x100G AC Chassis
        subject_str = ""
        # Check SerialNumber
        if "SerialNumber" in dict_for_subject:
            subject_str += "Serial Number={}, ".format(dict_for_subject["SerialNumber"])
        # Check Organization
        if "Organization" in dict_for_subject:
            subject_str += "O={}, ".format(dict_for_subject["Organization"])
        # Check Organizational Unit
        if "Organizational Unit" in dict_for_subject:
            subject_str += "OU={}, ".format(dict_for_subject["Organizational Unit"])

        if subject_str:
            # Print the formatted message
            if "Common Name" in dict_for_subject:
                print("{:>{}}{}".format("", 2, "Subject: " + subject_str))
                print("{:>{}}{}".format("", 11, "Name={}".format(dict_for_subject["Common Name"])))
            else:
                # Remove the trailing comma and space before printing
                subject_str = subject_str.rstrip(", ")
                print("{:>{}}{}".format("", 2, "Subject: " + subject_str))
        elif "Common Name" in dict_for_subject:
            print("{:>{}}{}".format("", 2, "Subject: Name={}".format(dict_for_subject["Common Name"])))
        subject_str = ""

        #Print Issuer 
        issuer_str = ""
        if "Common Name" in dict_for_issuer:
            issuer_str += "CN={}, ".format(dict_for_issuer["Common Name"])
        if "Organization" in dict_for_issuer:
            issuer_str += "O={}, ".format(dict_for_issuer["Organization"])
        if issuer_str:
            # Remove the trailing comma and space before printing
            issuer_str = issuer_str.rstrip(", ")
            print("{:>{}}{}".format("", 2, "Issuer : " + issuer_str))
        issuer_str = ""

        print("{:>{}}{}".format("", 2, "Validity"))
        if sys.version_info >= (3, 6):
            print("{:>{}}{}{}".format("", 4, "Not Before: ", cert.not_valid_before_utc))
            print("{:>{}}{}{}".format("", 4, "Not After : ", cert.not_valid_after_utc))
        else:
            print("{:>{}}{}{}".format("", 4, "Not Before: ", cert.not_valid_before))
            print("{:>{}}{}{}".format("", 4, "Not After : ", cert.not_valid_after))


    def VerifySUDIcerts(self):
        try:
            certs = self.SUDI_certs["system-certificates"]
        except:
            print("Invalid JSON, first expected key is system-certificates")
            sys.exit(1)

        if self.input_sudicert_file:
            print("Reading CiscoSUDI JSON data from input file: {}".format(self.input_sudicert_file))
            print("Connection specific Nonce Validation will be skipped")

        for node in certs:
            print("-" * 40)
            print("Verifying SUDI Certificate for node: {}".format(node["node-location"].replace("node","").replace("_","/")))
            nonce             = base64.b64decode(node["nonce"])
            signature_version = node["signature_version"]
            version_bin       = struct.pack('>i', signature_version)
            signature         = base64.b64decode(node["signature"])

            # Using cryptography module
            # base64 decode of certificates from JSON file 

            certificates = ["", "", ""]

            for cert in node["certificates"]["certificate"]:
                if cert["name"] == "Cisco SUDI Root":
                    certificates[0] = base64.b64decode(cert["value"])
                elif cert["name"] == "Cisco SUDI CA":
                    certificates[1] = base64.b64decode(cert["value"])
                else:
                    certificates[2] = base64.b64decode(cert["value"])
            

            # Load certificates from DER format
            sudi_root = self.LoadCertificateFromDer(certificates[0])
            if sudi_root:
                sudi_ca   = self.LoadCertificateFromDer(certificates[1])
                if sudi_ca:
                    sudi_leaf = self.LoadCertificateFromDer(certificates[2])
                    if sudi_leaf is None:
                        continue
                else:
                    continue
            else:
                continue


            # Validation of SUDI Signature
            # Verify data is signed by SUDI leaf
            data = b""
            data += nonce
            data += version_bin
            for cert in certificates:
                data += cert

            try:
                sudi_leaf.public_key().verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
                print("SUDI Signature Validated Successfully")
            except cryptography.exceptions.InvalidSignature:
                print("SUDI Signature Validation Failed")
                continue


            # Nonce Validation
            if self.input_sudicert_file is None:
                # Must Validate the connection specific Input nonce with the nonce present in SUDI cert JSON output file
                nonce_json  = binascii.hexlify(nonce).decode('utf-8')
                nonce_input = self.platform_security.GetNonce()
                if nonce_json == nonce_input:
                    print("Nonce Validated Successfully, expected: {} received: {}".format(nonce_input, nonce_json))
                else:
                    print("Nonce Validation Failed, expected: {} received: {}".format(nonce_input, nonce_json))
                    continue

            # Print SUDI Certificate Info
            print("SUDI Certificate Info: ")
            self.PrintCertInfo(cert=sudi_leaf)

            # Verify the chain of certificates
            try:
                # Verify sudi_lef(leaf certificate) against the sudi_ca(intermediate certificate)
                sudi_ca.public_key().verify(sudi_leaf.signature,
                        sudi_leaf.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        sudi_leaf.signature_hash_algorithm)
                # Verify sudi_ca(intermediate certificate) against the sudi_root(root certificate)
                sudi_root.public_key().verify(sudi_ca.signature,
                        sudi_ca.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        sudi_ca.signature_hash_algorithm)
                print("SUDI Certificate Chain Validated Successfully.")
            except cryptography.exceptions.InvalidSignature:
                print("SUDI Certificate Chain Validation Failed")
                continue


            # Checking if SUDI Root and SUDI CA are Cisco Certificates 
            # Retrieve issuer attributes
            dict_for_issuer  = self.GetCertIssuerDict(cert=sudi_leaf)

            if dict_for_issuer.get("Common Name"):
                if "High Assurance SUDI CA" in dict_for_issuer["Common Name"]:
                    # High Assurance SUDI CA
                    # Validate SUDI Root with Cisco rootCA
                    # Validate SUDI CA with Cisco subCA
                    if not self.cisco_rootCA_cert_2099:
                        print("Need Cisco rootCA(CN=Cisco Root CA 2099) Certificate to confirm SUDI Root)")
                        continue

                    if not self.cisco_subCA_cert_HAsudi:
                        print("Need Cisco subCA(CN=High Assurance SUDI CA) Certificate to confirm SUDI CA)")
                        continue

                    if (not self.Compare_cisco_subCA_with_sudiCA(flag_subCA_HAsudi=True, sudiCA=sudi_ca) or
                            not self.Compare_cisco_rootCA_with_sudiRoot(flag_rootCA_cert_2099=True, sudiRoot=sudi_root)):
                        continue
                else:
                    # ACT2 SUDI CA 
                    # Validate SUDI Root with Cisco rootCA
                    # Validate SUDI CA with Cisco subCA
                    if not self.cisco_rootCA_cert_2048:
                        print("Need Cisco rootCA(CN=Cisco Root CA 2048) Certificate to confirm SUDI Root)")
                        continue

                    if not self.cisco_subCA_cert_ACT2sudi:
                        print("Need Cisco subCA(CN=ACT2 SUDI CA) Certificate to confirm SUDI CA)")
                        continue

                    if (not self.Compare_cisco_subCA_with_sudiCA(flag_subCA_HAsudi=False, sudiCA=sudi_ca) or
                            not self.Compare_cisco_rootCA_with_sudiRoot(flag_rootCA_cert_2099=False, sudiRoot=sudi_root)):
                        continue
            else:
                print("Failed to retrieve issuer CommonName(CN) from SUDI Certificate")
                continue

            print("SUDI Certificate Verification Complete for node: {}".format(
                node["node-location"].replace("node","").replace("_","/")))

            print("-" * 40)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Validate SUDI Cert Output JSON file.')
    parser.add_argument('--input', metavar='JSON_file', type=str, help='Path to the SUDI Cert Output JSON file')
    args = parser.parse_args()
    if args.input:
        cisco_sudi = CiscoSUDI(args.input)
    else:
        cisco_sudi = CiscoSUDI(None)
