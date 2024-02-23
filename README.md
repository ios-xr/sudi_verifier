# sudi_verifier
This project aims to help detect counterfeit Cisco routers in the field. It helps with cryptographic validation of the device using Cisco’s SUDI.

SUDI stands for Secure Unique Device Identifier which is a unique per-device certificate (based on IEEE 802.1AR) programmed into the [TAm chip]( https://www.cisco.com/c/dam/en_us/about/doing_business/trust-center/docs/trustworthy-technologies-datasheet.pdf) (security chip on the card) during the device manufacturing. It’s unique per card (one per RP, LC, etc.). This SUDI certificate can be used to establish the hardware identity of the devices cryptographically. A user can challenge the devices to return a signed response along with the device unique SUDI certificate. The device would sign the response with the device unique SUDI private key. By validating the signature and the SUDI certificate chain, one can establish the hardware identity uniquely.

The scope of this project is only for Cisco’s IOS-XR based routing platforms. The provided scripts can be used to verify the hardware identity of any IOS-XR based router. The script supports both standalone and modular systems (with multiple RPs, LCs, etc.).

Dependencies to run the scripts – The requirements.txt file has the list of python libraries needed to run the scripts. Please use pip3 install or other methods to install the required libraries.

**Steps to run the scripts** – The script supports 2 modes of execution as explained below.

**Mode#1 - Full Mode**

1.	In this mode, the script fetches the JSON output of the SUDI certificate and does the validation.
2.	Below steps are performed in this mode
a.	The script connects to the target router over SSH.
b.	The script then executes the required CLI (including a unique nonce to ensure the freshness of the response) to fetch the signed SUDI certificate in JSON format.
c.	Lastly, the script verifies the signature, validates the nonce and then verifies the SUDI certificate chain.
3.	For connecting to the router, the config.ini file in the current working directory will be used. The hostname and other details needed for connecting to the router can be provided in this file.
4.	We highly recommend using password less method of connecting over SSH. However, the script also supports password-based authentication for quick prototyping. Please refer to the note below on authentication methods for more details.
5.	Once all the validation passes, the corresponding metadata from the SUDI certificate is also displayed.
6.	The fetched JSON output with the corresponding timestamp for each execution is stored in a directory named “output” within the current working directory. Sample format of the output filename is “sudi_certs_2024-01-31_17-37-24.json”.
7.	The cert chain validation uses the Cisco public certs for the corresponding platforms. The required public certs have been pre-downloaded in the “certs” directory. 

ACT2SUDICA.pem
crca2048.pem
crca2099.pem
hasudi.pem

Alternatively, users can download the certs from here - https://www.cisco.com/security/pki/

The required certificates for IOS-XR routing platforms are,

**Root CA certs**

1. [crca2048.pem](https://www.cisco.com/security/pki/crl/crca2048.crl)
2. [crca2099.pem](https://www.cisco.com/security/pki/crl/crca2099.crl)

**Sub-CA certs**

1. [ACT2 SUDI CA.pem](https://www.cisco.com/security/pki/certs/ACT2SUDICA.pem)
2. [HA SUDI.pem](https://www.cisco.com/security/pki/certs/hasudi.pem)

**Mode#2 - Verification Only Mode**
1.	In this mode, the script can be used to just verify the SUDI certificate that was already fetched by the user through any other existing automation mechanisms.
2.	The JSON file that was pre-fetched can be provided as an input with the option “--input” and the path to the JSON file.
3.	In this case the JSON file provided will be parsed and the SUDI certificate chain validation will be performed. The corresponding metadata from the SUDI certificate will also be displayed.
4.	For the cert chain validation, as mentioned in step#4 above, the pre-downloaded public certificates can be used, or users can download the public certificates again from the provided links above.

**Authentication Methods**

**We do not recommend** storing the passwords for production routers in plaintext in such config files. The script gives preference to public-key based authentication first if available and falls back to password method only if key based authentication is not supported in your environment.
Additional, protection measures like encrypting the password string in the config.ini file can be considered where the encryption key is fetched during execution from a different location. Depending on your environment, appropriate measures must be taken if using password-based authentication.
Best case would be to use key or certificate-based authentication supported by IOS-XR routers.

**Script options –**

linux_user# ./verify_sudi_certs.py -h
usage: verify_sudi_certs.py [-h] [--input JSON_file]

Validate SUDI Cert Output JSON file.

options:
  -h, --help         show this help message and exit
  --input JSON_file  Path to the SUDI Cert Output JSON file

