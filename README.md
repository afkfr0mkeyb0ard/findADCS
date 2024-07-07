# Description
Python scripts to find ADCS servers on a network without any credentials.
Clone and install the requirements:
```
$ git clone https://github.com/afkfr0mkeyb0ard/findADCS.git
$ cd findADCS
$ python3 -m pip install -r requirements.txt
```

## 1. Using web exposure
ADCS may expose Web page for cert enrollment. By scanning the Web ports we can find out the ADCS IP:

    $ python3 scanWeb.py <TARGET>

**TARGET** *can be a single IP, a file containing IP or a network*

#### Scanning a single IP:
    $ python3 scanWeb.py 10.10.10.1

#### Scanning a list of IP (one per line):
    $ python3 scanWeb.py FILE

#### Scanning a network:
    $ python3 scanWeb.py 10.10.10.0/24

By default, the script scans ports 80 and 443 but you can change it in the script.

## 2. Using certs issuers
Among the exposed services using SSL/TLS, some may have an internal Cert issuer, which is probably the ADCS server.
This script lists the issuers found among the SSL certs:

    $ python3 scanCerts.py <TARGET>

**TARGET** *can be a single IP, a file containing IP or a network*

#### Scanning a single IP:
    $ python3 scanCerts.py 10.10.10.1

#### Scanning a list of IP (one per line):
    $ python3 scanCerts.py FILE

#### Scanning a network:
    $ python3 scanCerts.py 10.10.10.0/24

By default, the script scans ports 443,636 and 8443 but you can change it in the script.
