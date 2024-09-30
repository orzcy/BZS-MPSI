FROM ubuntu:22.04

RUN apt-get update && \
apt-get install -y build-essential cmake git libtool iproute2 python3 sudo && \
rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN git clone https://github.com/orzcy/BZS-MPSI.git

WORKDIR /app/BZS-MPSI

RUN python3 build.py -DVOLE_PSI_ENABLE_BOOST=ON && \
rm -rf ./out/bitpolymul ./out/boost_1_86_0 ./out/coproto ./out/function2 \
./out/libdivide ./out/libOTe ./out/libsodium ./out/macoro

