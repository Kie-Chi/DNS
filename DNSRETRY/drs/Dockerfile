FROM ubuntu:20.04
# Use noninteractive to avoid prompts
ENV DEBIAN_FRONTEND noninteractive

# Update and install required system packages
RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get -y install build-essential libssl-dev libperl-dev libcap-dev wget vim tar dnsutils pkg-config \
    python3 python3-pip python3-dev perl xz-utils
RUN apt-get -y install bind9utils
RUN pip3 install ply

RUN apt-get install -y libexpat1-dev libssl-dev tcpdump

ENV version 1.17.1
RUN wget https://nlnetlabs.nl/downloads/unbound/unbound-${version}.tar.gz \
    && tar -xzvf unbound-${version}.tar.gz \
    && rm unbound-${version}.tar.gz

# Build and install Unbound from the source code
RUN cd unbound-${version} \
    && ./configure \
    && make \
    && make install

# Create unbound user and group
RUN groupadd -r unbound && useradd -r -g unbound unbound

# Run Unbound in the foreground
CMD ["unbound", "-d"]