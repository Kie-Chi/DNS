# =================================================================
# 第一阶段: 构建环境 (Builder)
# =================================================================
# 使用与原始文件相同的 Fedora 37 基础镜像
FROM fedora:37 AS builder

# Git 提交哈希，可以按需修改
ARG VERSION=463644c83a93db3d20d574450f1106a2d0b627b9
ARG PROGRAM=resolved

# 1. 安装构建依赖
# - git: 用于克隆源码
# - cargo, rust: Rust 工具链
# - openssl-devel: resolved 依赖的 openssl 库的开发文件
# - gcc: C 语言编译器，某些 Rust 依赖的库在构建时需要
RUN dnf install -y --setopt=tsflags=nodocs --setopt=install_weak_deps=False \
    git cargo rust openssl-devel gcc \
    && dnf clean all

WORKDIR /app

# 2. 克隆指定版本的源码
RUN git clone https://github.com/barrucadu/resolved.git \
    && cd "${PROGRAM}" \
    && git checkout "${VERSION}"

# 3. 编译 release 版本的二进制文件
#    我们直接在 Dockerfile 中执行编译，不再需要 build.sh 脚本
RUN cd "${PROGRAM}" && cargo build --release --bin resolved


# =================================================================
# 第二阶段: 运行环境 (Final Image)
# =================================================================
FROM fedora:37

ARG PROGRAM=resolved

# 安装运行时的最小依赖
# - openssl-libs: resolved 动态链接的 openssl 库
# - ca-certificates: 用于 TLS/HTTPS 请求的根证书
RUN dnf install -y --setopt=tsflags=nodocs --setopt=install_weak_deps=False \
    openssl-libs ca-certificates tmux dnsutils tcpdump \
    && dnf clean all

# 1. 从 builder 阶段拷贝编译好的二进制文件
COPY --from=builder /app/${PROGRAM}/target/release/resolved /usr/local/sbin/resolved

# 2. 准备 resolved 所需的配置文件目录和根域名提示文件
#    这个 root.hints 文件对于递归解析器至关重要
RUN mkdir -p /etc/resolved/zones/
# 3. 创建一个用于存放用户自定义配置的目录，并设置为 VOLUME
RUN mkdir /config
VOLUME [ "/config" ]

# 4. 暴露 DNS 协议的标准端口
EXPOSE 53/tcp 53/udp

# 5. 设置入口点和默认命令
#    程序会读取 /config/config.toml 文件作为配置
ENTRYPOINT [ "/usr/local/sbin/resolved" ]
CMD [ "-Z", "/etc/resolved/zones" ]