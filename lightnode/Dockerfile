FROM ubuntu:20.04

COPY lightnode_workspace/ /workspace/

RUN cp /workspace/sources.list /etc/apt/ \
    && cp /workspace/geth-linux-amd64-1.8.12-37685930/geth /usr/bin \
    && apt update \
    && apt install net-tools -y \
    && apt install python3 -y \
    && apt install python3-pip -y \
    && pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple \
    && pip install asn1crypto \
    && pip install python-dateutil \
    && pip install django \
    && pip install web3==5.0.2 \
    && pip install pymysql \
    && geth -datadir ~/data/ init /workspace/genesis.json