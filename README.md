# Network Sniffer
## Installation
1. Clone the repository:
```
git clone https://github.com/AshStorm17/Sniffer.git
cd Sniffer
```

2. Install the required dependencies:
```
pip install -r requirements.txt
```

## Usage
To run the sniffer use:
```
sudo python3 sniffer.py <time>
```
Simultaneously run
```
sudo tcpreplay -i eth0 --pps=1000 7.pcap
```
The pps argument is optional but recommended.

## Note:
The 7.pcap file need to be added to the root folder after cloning.
