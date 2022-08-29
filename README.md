# System building steps

First, you need to deploy the MySQL server and create the initial node. After the smart contract is deployed to the initial node by using tuffle, and the contract address is obtained, modify the contract address in the full node folder, and then create the full node and the light node.



## 1. Deploy MySQL server

First create the docker network, then start the MySQL container, and set the root password of Mysql to test.

```shell
sudo docker network create -d bridge --subnet=172.18.0.0/16 ethnet

docker run --network ethnet --ip 172.18.0.49 --name mysql -v

~/cablockchain/workspace/mysql/conf:/etc/mysql/conf.d -v

~/cablockchain/workspace/mysql/logs:/logs -v

~/cablockchain/workspace/mysql/data:/var/lib/mysql -e MYSQL_ROOT_PASSWORD=test -d mysql:5.7
```



## 2. Create initial node

The dockerfile content is:

```dockerfile
FROM ubuntu:20.04

COPY initnode_workspace/ /workspace/

RUN cp /workspace/sources.list /etc/apt/ \

     && cp /workspace/geth-linux-amd64-1.8.12-37685930/geth /usr/bin \

     && geth -datadir ~/data/ init /workspace/genesis.json \

     && cp -r /workspace/keystore/* ~/data/keystore/
```



Under the directory of dockerfile, build the docker image:

```shell
docker build -t initnode:v1 .
```



Start container:

```shell
docker run -it --name=init --network ethnet --ip 172.18.0.50 initnode:v1
```



Start full nodes

```shell
geth -datadir ~/data/ --lightserv 50 --networkid 88 --rpc --rpcaddr "172.18.0.50" --rpcapi admin,eth,miner,web3,personal,net,txpool console
```



In the geth console, unlock the account and start mining

```
personal.unlockAccount(eth.accounts[0],'test',10000)

miner.start()
```



In `~/cablockchain/contract/` directory, use truffle e to deploy smart contracts into the blockchain

```shell
truffle migrate --network development
```



Get the contract address and fill in the contract address
`~/cablockchain/fullnode/fullnode_workspace/fullnode_server/server`  in Web3util.py 

![image-20220829103518990](C:\Users\77142\AppData\Roaming\Typora\typora-user-images\image-20220829103518990.png)



Stop mining after deployment. (in the test environment, start mining when you want to send a transaction)

```shell
miner.stop()
```





## 3. Create a full node server

The content of dockerfile is:

```dockerfile
FROM ubuntu:20.04
COPY fullnode_workspace/ /workspace/
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
     && geth -datadir ~/data/ init /workspace/genesis.json \
     && cp -r /workspace/keystore/* ~/data/keystore/
     
```



Under the directory of dockerfile, build a docker image:

```shell
docker build -t fullnode:v1 .
```



Start container:

```shell
docker run -it --name=fullnode1 --network ethnet --ip 172.18.0.51 fullnode:v1
```



**Start full nodes**

```shell
geth -datadir ~/data/ --lightserv 50 --networkid 88 --rpc --rpcaddr "172.18.0.51" --rpcapi admin,eth,miner,web3,personal,net,txpool console
```



Connect full nodes to the initial node (or other full nodes).

On the geth console of the initial node, use the `admin.nodeInfo.enode` command to view the P2P address

Then, on the newly started full node console, use the `admin.addPeer` command to connect the initial node. Note that the port is modified to the ip of the initial node.

![image-20220829104636826](C:\Users\77142\AppData\Roaming\Typora\typora-user-images\image-20220829104636826.png)



The more the new full nodes connect to the rest of the network, the better the synchronization performance



**Start the server**

Open another terminal using `docker exec`

In the other terminal, start the django server.

```shell
python3 workspace/lightnode_server/manage.py runserver 0.0.0.0:8000
```





# Project structure

The project folder structure is as follows:

![image-20220829105852453](C:\Users\77142\AppData\Roaming\Typora\typora-user-images\image-20220829105852453.png)



![image-20220829105903066](C:\Users\77142\AppData\Roaming\Typora\typora-user-images\image-20220829105903066.png)

It is mainly divided into five folders: `contract, fullnode, lightnode, initnode and workspace`.

`contract` is the folder used to develop smart contracts. `truffle` is used to develop and deploy contracts. `contract/contracts` is the contract file.

The `fullnode` folder is used to deploy all nodes, including `dockerfile` and `fullnode_ workspace`. `dockerfile` is used to build a docker image, `fullnode_server` in  `fullnode_workspace` folder of the full node server. Here, django is used to build the web server.



`fullnode_ server` file structure is as follows:

![image-20220829114026089](C:\Users\77142\AppData\Roaming\Typora\typora-user-images\image-20220829114026089.png)



`views.py` is the code to implement the server interface, `pkcs7util.py` is the code to implement the pkcs7 file processing, and `web3util.py` is the content required to connect with the smart contract.



`lightnode` folder is used to deploy light nodes. The structure is similar to the `fullnode` folder.



`workspace` folder is a number of public files, including MySQL databases.





# Results display

## Interface test

Create CA certificate

![image-20220829143621005](C:\Users\77142\AppData\Roaming\Typora\typora-user-images\image-20220829143621005.png)



Light nodes apply for identity certificates.

![image-20220829143726070](C:\Users\77142\AppData\Roaming\Typora\typora-user-images\image-20220829143726070.png)

The authorized person applies for the authorization certificate from the authorizer.

![image-20220829143854535](C:\Users\77142\AppData\Roaming\Typora\typora-user-images\image-20220829143854535.png)

The authorized person applies for the information of the authorized person.

![image-20220829144109781](C:\Users\77142\AppData\Roaming\Typora\typora-user-images\image-20220829144109781.png)



Apply for revocation of certificate.

![image-20220829144209853](C:\Users\77142\AppData\Roaming\Typora\typora-user-images\image-20220829144209853.png)


## Blockchain testing

The system uses the Ethereum client geth to build a private chain. After the successful building, each full node is connected with 6 other nodes, including 2 light nodes and 4 full nodes.

Through the geth command line, you can see that the current node is connected to 6 nodes, and you can see the connection details.

![image-20220829143259747](C:\Users\77142\AppData\Roaming\Typora\typora-user-images\image-20220829143259747.png)

![image-20220829143312279](C:\Users\77142\AppData\Roaming\Typora\typora-user-images\image-20220829143312279.png)