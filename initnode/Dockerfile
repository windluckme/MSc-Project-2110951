FROM ubuntu:20.04

COPY initnode_workspace/ /workspace/

RUN cp /workspace/sources.list /etc/apt/ \
    && cp /workspace/geth-linux-amd64-1.8.12-37685930/geth /usr/bin \
    && geth -datadir ~/data/ init /workspace/genesis.json \
    && cp -r /workspace/keystore/* ~/data/keystore/