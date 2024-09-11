FROM ubuntu:22.04
RUN apt-get -y update && apt-get install -y git
RUN apt-get install -y build-essential
RUN apt-get install -y cmake
RUN apt-get install -y python3
RUN apt-get install -y libssl-dev
RUN apt-get install -y libtool
WORKDIR /app
RUN git clone https://github.com/orzcy/BZS-MPSI.git
WORKDIR /app/BZS-MPSI
RUN python3 build.py -DVOLE_PSI_ENABLE_BOOST=ON
