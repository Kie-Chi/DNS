# =================================================================
# 第一阶段: 构建环境 (Builder)
# =================================================================
FROM fedora:37 AS builder

# Hickory DNS (原 trust-dns) 的 Git 提交哈希 (对应 v0.22.0)
ARG VERSION=0b6fefea3fefe1086fed4df6781550462de51553
ARG PROGRAM=hickory-dns

# 1. 安装构建依赖
RUN dnf install -y --setopt=tsflags=nodocs --setopt=install_weak_deps=False \
    git cargo rust openssl-devel gcc \
    && dnf clean all

WORKDIR /app

# 2. 克隆新仓库指定版本的源码
RUN git clone https://github.com/hickory-dns/hickory-dns.git \
    && cd "${PROGRAM}" \
    && git checkout "${VERSION}"

# 3. 编译 release 版本的二进制文件
#    --features recursor 启用递归解析器功能
#    --bin hickory-dns 指定编译主程序二进制文件
RUN cd "${PROGRAM}" && cargo build --release --features recursor --bin trust-dns


# =================================================================
# 第二阶段: 运行环境 (Final Image)
# =================================================================
FROM fedora:37

ARG PROGRAM=hickory-dns

# 安装运行时的最小依赖
RUN dnf install -y --setopt=tsflags=nodocs --setopt=install_weak_deps=False \
    openssl-libs ca-certificates \
    && dnf clean all

# 1. 从 builder 阶段拷贝编译好的二进制文件
COPY --from=builder /app/${PROGRAM}/target/release/trust-dns /usr/local/sbin/hickory-dns

# 2. 准备 hickory-dns 所需的配置文件目录和根域名提示文件
#    文件路径在仓库中未变，但我们放到新的配置目录下
RUN mkdir -p /etc/hickory-dns/ && \
    mkdir -p /usr/local/etc/hickory-dns

# 3. 创建一个用于存放用户自定义配置的目录，并设置为 VOLUME
RUN mkdir /config
VOLUME [ "/config" ]

# 4. 暴露 DNS 协议的标准端口
EXPOSE 53/tcp 53/udp

# 5. 设置入口点和默认命令
#    程序名已更新为 hickory-dns
ENTRYPOINT [ "/usr/local/sbin/hickory-dns" ]
CMD [ "--debug", "--config=/usr/local/etc/hickory-dns/hickory-dns.toml" ]