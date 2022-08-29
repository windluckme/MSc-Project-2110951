from web3 import Web3
from web3 import Account
import json, os
from . import func

web3 = Web3(Web3.HTTPProvider('http://172.18.0.50:8545'))

#Contract abi
with open(os.path.join(func.tests_root, 'abi/Hash_SC_abi.json'), 'r') as f:
    hash_sc_abi = json.loads(f.read())
with open(os.path.join(func.tests_root, 'abi/Id_CA_abi.json'), 'r') as f:
    id_ca_abi = json.loads(f.read())
with open(os.path.join(func.tests_root, 'abi/Au_CA_abi.json'), 'r') as f:
    au_ca_abi = json.loads(f.read())

#Contract address:
hash_sc_address = '0x960F43c489768BFbd84A3853AD757F0F00dDAbD5'
id_ca_address = '0xA89bd506534e384783575B240Fa44844b9378744'
au_ca_address = '0x384cf0f8F167D00F3B1D7852465a904F7753e7Cf'

#geth
# hash_sc_address = '0x0D8a528a352d0ccDB9761093e14D21661c6D0752'
# id_ca_address = '0x7D3CC1d0d264aC2Bf4Ae8B7e0026833cBAFaa098'
# au_ca_address = '0x4625Be6E046241173D68F4d3c2FF5ea6876CB83d'

#Contract object
Hashsc = web3.eth.contract(address=hash_sc_address, abi=hash_sc_abi)
Idca = web3.eth.contract(address=id_ca_address, abi=id_ca_abi)
Auca = web3.eth.contract(address=au_ca_address, abi=au_ca_abi)

def getPrivateKey_CA(password):
    with open(os.path.join(func.tests_root, 'cainfo/UTC--2022-07-30T12-16-50.434345954Z--c676f75f9542f624aacbe99d0118e945b97041ab'),'r') as f:
        privatekey = Account.decrypt(f.read(), password)
    return privatekey