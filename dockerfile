FROM ubuntu:22.04 AS builder

RUN apt-get update && \
apt-get install -y build-essential cmake git libtool iproute2 python3 sudo && \
rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN git clone https://github.com/orzcy/BZS-MPSI.git

WORKDIR /app/BZS-MPSI

ARG ENVIRONMENT

RUN if [ "$ENVIRONMENT" = "x86SSE" ]; then \
        python3 build.py -DVOLE_PSI_ENABLE_BOOST=ON -DVOLE_PSI_ENABLE_BITPOLYMUL=OFF;\
    elif [ "$ENVIRONMENT" = "x86NOSSE" ]; then \
        python3 build.py -DVOLE_PSI_ENABLE_BOOST=ON -DVOLE_PSI_ENABLE_SSE=OFF -DVOLE_PSI_ENABLE_BITPOLYMUL=OFF; \
	elif [ "$ENVIRONMENT" = "ARM" ]; then \
        python3 build.py -DVOLE_PSI_ENABLE_BOOST=ON -DVOLE_PSI_ENABLE_SSE=OFF -DVOLE_PSI_ENABLE_BITPOLYMUL=OFF -DVOLE_PSI_ENABLE_SODIUM=ON -DVOLE_PSI_ENABLE_RELIC=OFF; \
	else \
        echo "Unsupported architecture: $ENVIRONMENT"; \
        exit 1; \
fi

FROM ubuntu:22.04

WORKDIR /app

COPY --from=builder /app/BZS-MPSI/out/build /app/BZS-MPSI/out/build 

WORKDIR /app/24-Efficient-Private-Set-Intersection/out/build/linux/frontend