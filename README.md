# Created for a Data Communications Project
Professor: Dr. Ostermann, EECS department at Ohio University<br>
Tools provided by our GA: Silas Springer

## Project expectations:
This assignment is intended to tie together all of the concepts that we’ve discussed so far. You’re going to
build a tiny networking operating system called “twig” (like Juniper, but much, much smaller). Your Twig
operating system was a single network interface and can only respond to packets.
1. Respond to ICMP echo requests
2. Contain a simple ARP cache
3. Understand and demultiplex the UDP protocol
4. Implement a server on the UDP echo port (see RFC 862)
5. Implement a server on the UDP ”Time Protocol” port (see RFC 868)
6. IP/UDP/TCP Checksums. To be able to talk to external programs (more on that later), it will be
necessary to implement IP, ICMP, and UDP checksums
7. Hardware Addresses and ARP. For now, since we’re only responding to incoming packets, your
ARP cache will simply be populated by the mappings in incoming packets
8. Keep in mind that you will be expanding the program in a couple of weeks to support routing tables,
packet forwarding, and more advanced processing, so be sure to keep your interfaces clean and use
lots of functions that can be reused later


## Directory Tree
```bash
Twig
├── Makefile
├── README.md
├── old
│   ├── Makefile
│   ├── tcarp
│   ├── tcarp-utils.h
│   ├── tcarp.cc
│   └── tcarp.o
├── output
├── requirements.txt
├── tools
│   ├── 172.31.128.0_24.dmp
│   ├── README.md
│   ├── make_pcap.sh
│   ├── shim.py
│   ├── socket_time
│   ├── socket_time.c
│   └── twig_test.sh
├── twig-utils.h
├── twig.cc
├── twig_tester.sh
└── udp_ping
    ├── COPYRIGHT
    ├── Makefile
    ├── README.md
    ├── connectsock.c
    ├── connectsock.o
    ├── hist.c
    ├── hist.o
    ├── misc.c
    ├── misc.o
    ├── netutils.c
    ├── netutils.o
    ├── udpping
    ├── udpping.c
    ├── udpping.h
    └── udpping.o
```
Where:
- The current working directory will be my code intended to accomplish the project.
- Tools is a list of tools provided to help work on this project.
- udp_ping is a list of tools provided to help debug UDP related portions of the assignment.
- Old is code from previous projects relevant to this.

## Running the project
**IMPORTANT** note:
- Uhhhh I'm skilled with bash but not *that* much.
- Create a venv for python because you'll need certain packages (create in Twig root).
```sh
$ python -m venv .venv
$ pip install -r requirements.txt
```
- I edited the original tools file so it works with a venv but it's hardcoded.

The tools are used to create the pcap dmp file. It does not close on it's own (not my fault). You'll have to ^C it and then close the terminal (or ^\).<br>

### tools/twig_test.sh
This is how we actively keep our eyes open for ping requests and such.
```sh
$ cd tools
$ sudo ./twig_test.sh
```
Then if you ping the IP {172.31.128.*} it *should* write to the file.

### twig_tester.sh
Designed to run on the IP, but could be configured to use different dmps (not required on my end so I won't). <br>
To run on the hardcoded IP (root is required):
```sh
$ sudo twig_tester.sh
```
This will run make on twig and run the required tools.
```sh
Usage for normal: ./twig filename
Usage for debug types where -d is for full debug and -dt is for twig debug: ./twig [-d,-td] filename
Usage for ARP cache output: ./twig -a filename
Usage for help: ./twig -h OR ./twig --help
``` 
Where:
- -h or --help prints usage
- -d is a very verbose, mostly outdated debug of all things IP and TCP.
- -td is a more accurate debug feature.
- -a will print out a theoretical ARP cache. Not super functional, but will be in future implementations


### twig
If you don't want to use twig_tester, you can:
```sh
$ make
$ sudo ./twig [args] [filename]
```
To test, you can ping, UDP ping, or UDP time request utilizing different tools.<br>
You need tools/twig_test.sh running and twig running to test, but I believe in your, the tester's, capabilities.
