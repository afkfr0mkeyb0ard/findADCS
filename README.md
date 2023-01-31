# findADCS
Python script to find ADCS servers on a network

    $ python3 findADCS.py [TARGET]

[TARGET] *can be a single IP, a file containing IP or a network*

#### Scanning a single IP:
    $ python3 findADCS.py 10.10.10.1

#### Scanning a list of IP (one per line):
    $ python3 findADCS.py FILE

#### Scanning a network:
    $ python3 findADCS.py 10.10.10.0/24
