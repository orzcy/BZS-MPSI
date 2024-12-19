# BZS-MPSI

BZS-MPSI implements the protocols described in our paper [**Efficient Scalable Multi-Party Private Set Intersection(-Variants) from Bicentric Zero-Sharing (ACM CCS 2024)**](https://dl.acm.org/doi/10.1145/3658644.3690245), which also gets the `Artifacts Evaluated` badge.

When using BZS-MPSI to achieve the MPSI functionality, the part of two-party PSI being invoked is based on [Vole-PSI](https://github.com/Visa-Research/volepsi) from [VOLE-PSI: Fast OPRF and Circuit-PSI from Vector-OLE](https://eprint.iacr.org/2021/266) and [Blazing Fast PSI from Improved OKVS and Subfield VOLE](https://eprint.iacr.org/2022/320.pdf). And thanks to the recent updates and optimizations of Vole-PSI by its contributors, the communication cost of Leader and Pivot in BZS-MPSI will be reduced compared to that presented in Table 5 of our paper.

## Building the project

The project can be built in a Linux system with networking support using the following instructions. The recommended versions are ``Ubuntu:22.04 LTS, g++ 11.4.0, and CMake 3.22.1`` or higher. Otherwise, we highly suggest using the dockerfile-based approach introduced later for better reproducibility.

```shell
sudo apt-get update -y
sudo apt-get install -y build-essential gcc g++ libtool libssl-dev git iproute2 cmake=3.22.*

git clone https://github.com/orzcy/BZS-MPSI.git
cd BZS-MPSI
python3 build.py -DVOLE_PSI_ENABLE_BOOST=ON
```

After the building process, the executable `frontend` will be located at `out/build/linux/frontend`.

**We also provide some docker-based approaches to build the project.**

The dockerfile-based building approach:
```shell
git clone https://github.com/orzcy/BZS-MPSI.git
cd BZS-MPSI
docker build --no-cache -t [Your Image Name] .
docker run -itd --net=host --name [Your Container Name] --cap-add=NET_ADMIN [Your Image ID] /bin/bash
docker exec -it [Your Container ID] /bin/bash 
```

The docker-image-based building approach:
```shell
docker pull orzcy/bzs-di:latest
docker run -itd --net=host --name bzs-di --cap-add=NET_ADMIN orzcy/bzs-di:latest /bin/bash
docker exec -it bzs-di /bin/bash 
```
After the (docker-based) building process, the executable `frontend` will be located at `app/BZS-MPSI/out/build/linux/frontend` in the docker container.

## Running the code

Use the following instruction in `frontend` to run a participant:

```shell
./frontend -mpsi [Parameters]
```

Required parameters:
* `-in [value]`, value: the path to the party's set. The path should have a \".csv\" extension with one element with 32 char hex per row.
* `-out [value]`, value: the output file path (default "in || .out"). 
* `-nu [value]`, value: the number of participants.
* `-id [value]`, value: participant ID (the IDs of Clients range from 0 to nu-3, the ID of Pivot is nu-2, and the ID of Leader is nu-1).
* `-ipp [value]`, value: IP address and base port of Pivot.
* `-ipl [value]`, value: IP address and base port of Leader.

Optional parameters:
* `-nt [value]`, value: the number of threads allocated to the participant (default 1).
* `-la [value]`, value: the statistical security parameter (default 40).
* `-ca`, if this option appears, run MPSI-CA instead of MPSI (default false).
* `-bc`, if this option appears, Leader broadcasts the result at the end (default false).

There are some examples to illustrate how to run the code:

````shell
# Enter out/build/linux/frontend

cd out/build/linux/frontend

# Run MPSI with 4 participants (in 4 different terminals)
# The input files are P1~P4.csv
# Pivot's IP address is 192.168.0.10, and the base port is 10000
# Leader's IP address is 192.168.0.11, and the base port is 12000
# Leader computes the intersection and writes it to O4.csv

./frontend -mpsi -nu 4 -id 0 -in P1.csv -ipp 192.168.0.10:10000 -ipl 192.168.0.11:12000
./frontend -mpsi -nu 4 -id 1 -in P2.csv -ipp 192.168.0.10:10000 -ipl 192.168.0.11:12000
./frontend -mpsi -nu 4 -id 2 -in P3.csv -ipp 192.168.0.10:10000 -ipl 192.168.0.11:12000
./frontend -mpsi -nu 4 -id 3 -in P4.csv -out O4.csv -ipp 192.168.0.10:10000 -ipl 192.168.0.11:12000

# Run MPSI-CA with 4 participants (in 4 different terminals)
# Allocate 4 threads for Pivot (ID = 3) and Leader (ID = 4) each
# The input files are P1~P4.csv
# Pivot's IP address is 192.168.0.10, and the base port is 10000
# Leader's IP address is 192.168.0.11, and the base port is 12000
# Leader computes the size of the intersection and broadcasts it to all participants
# The output files are O1~O4.csv

./frontend -mpsi -nu 4 -id 0 -in P1.csv -out O1.csv -ipp 192.168.0.10:10000 -ipl 192.168.0.11:12000 -ca -bc
./frontend -mpsi -nu 4 -id 1 -in P2.csv -out O2.csv -ipp 192.168.0.10:10000 -ipl 192.168.0.11:12000 -ca -bc
./frontend -mpsi -nu 4 -id 2 -in P3.csv -out O3.csv -ipp 192.168.0.10:10000 -ipl 192.168.0.11:12000 -ca -bc -nt 4
./frontend -mpsi -nu 4 -id 3 -in P4.csv -out O4.csv -ipp 192.168.0.10:10000 -ipl 192.168.0.11:12000 -ca -bc -nt 4
````

**We also provide a benchmark based on a single machine, simulated networks, and random inputs.**

Use the following instruction in `frontend` to run the unit tests:
```shell
./frontend -u -mpsi
```

And use the following instruction in `frontend` to run a participant in benchmark:
```shell
./frontend -perf -mpsi [Parameters]
```

Required parameters:
* `-nu [value]`, value: the number of participants.
* `-id [value]`, value: participant ID (the IDs of Clients range from 0 to nu-3, the ID of Pivot is nu-2, and the ID of Leader is nu-1).
* `-nn [value]`, value: the log2 size of the set (default 10). In the benchmark, please enter the same `nn` for all participants.

Optional parameters:
* `-ts [value]`, value: the preset intersection size to verify the correctness (default 0.1*set size).
* `-nt [value]`, value: the number of threads allocated to the participant (default 1).
* `-la [value]`, value: the statistical security parameter (default 40).
* `-ca`, if this option appears, run MPSI-CA instead of MPSI (default false).
* `-bc`, if this option appears, Leader broadcasts the result at the end (default false).

There are some examples to illustrate how to run the benchmark:

````shell
# Enter out/build/linux/frontend

cd out/build/linux/frontend

# Run the unit tests

./frontend -u -mpsi

# Run MPSI benchmark with 5 participants, 2^20 set size, and preset the intersection size as 1000

./frontend -perf -mpsi -nu 5 -id 0 -nn 20 -ts 1000 & 
./frontend -perf -mpsi -nu 5 -id 1 -nn 20 -ts 1000 & 
./frontend -perf -mpsi -nu 5 -id 2 -nn 20 -ts 1000 & 
./frontend -perf -mpsi -nu 5 -id 3 -nn 20 -ts 1000 & 
./frontend -perf -mpsi -nu 5 -id 4 -nn 20 -ts 1000

# Run MPSI-CA benchmark with 5 participants, 2^16 set size
# Allocate 4 threads for Pivot (ID = 3) and Leader (ID = 4) each, and preset the intersection size as 100

./frontend -perf -mpsi -nu 5 -id 0 -nn 16 -ts 100 -ca & 
./frontend -perf -mpsi -nu 5 -id 1 -nn 16 -ts 100 -ca & 
./frontend -perf -mpsi -nu 5 -id 2 -nn 16 -ts 100 -ca & 
./frontend -perf -mpsi -nu 5 -id 3 -nn 16 -ts 100 -ca -nt 4 & 
./frontend -perf -mpsi -nu 5 -id 4 -nn 16 -ts 100 -ca -nt 4
````

The program will output the running time and communication cost of Client (ID = nu-3), Pivot (ID = nu-2), and Leader (ID = nu-1), along with the resulting intersection size obtained by Leader on the terminal.

In addition, we use `tc` command to set our LAN and WAN settings.

````shell
# LAN setting: 20Gbps rate, 0.02ms latency

sudo tc qdisc add dev lo root netem rate 20Gbit delay 0.02ms

# WAN setting: 200Mbps rate, 96ms latency

sudo tc qdisc add dev lo root netem rate 200Mbit delay 96ms

# Delete all the limits on "lo"

sudo tc qdisc del dev lo root
````
