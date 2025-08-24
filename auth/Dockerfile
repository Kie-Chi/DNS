FROM debian:12
# Use noninteractive to avoid prompts
ENV DEBIAN_FRONTEND noninteractive

# Update and install required system packages
RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get -y install build-essential libssl-dev libperl-dev libcap-dev wget vim tar dnsutils libuv1 pkg-config \
    python3 python3-pip python3-venv python3-dev python3-ply
RUN apt-get -y install libuv1-dev
RUN apt-get -y install bind9utils

ENV version 9.16.45

# Install BIND9 from source
RUN cd /usr/local/src && \
    wget https://downloads.isc.org/isc/bind9/${version}/bind-${version}.tar.xz && \
    tar xvf bind-${version}.tar.xz && \
    mv bind-${version} bind && \
    rm bind-${version}.tar.xz
RUN cd /usr/local/src/bind && \
    ./configure --enable-syscalls --prefix=/var/named/chroot --enable-threads --with-openssl --enable-openssl-version-check --enable-ipv6 --disable-linux-caps && \
    chown -R root:root /usr/local/src/bind && \
    make && \
    make install

# Create device files
RUN mkdir -p /var/named/chroot/dev && \
    mknod -m 666 /var/named/chroot/dev/null c 1 3 && \
    mknod -m 666 /var/named/chroot/dev/random c 1 8

# Create rndc key
RUN /var/named/chroot/sbin/rndc-confgen -a

RUN mkdir -p /var/named/chroot/data && \
    mkdir -p /var/named/chroot/var/log && \
    mkdir -p /var/named/chroot/var/named

# Create hint file
RUN cd /var/named/chroot/var/named && \
    wget https://www.internic.net/domain/named.root

# # Add files
# COPY ./contents/named.conf /etc/named.conf
# COPY ./contents/named /etc/default/named
# COPY ./contents/cache.db /var/named/chroot/var/named/cache.db

# Create symbolic link
RUN ln -s /var/named/chroot/etc/rndc.key /etc/rndc.key && \
    ln -s /var/named/chroot/etc/named.conf /etc/named.conf

RUN apt-get install -y tcpdump || apt-get install -y tcpdump --fix-missing

EXPOSE 53 953

CMD ["/var/named/chroot/sbin/named", "-g", "-t", "/var/named/chroot", "-c", "/etc/named.conf"]
