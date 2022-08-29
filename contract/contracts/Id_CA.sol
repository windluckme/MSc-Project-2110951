// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.9.0;

contract Id_CA{

    struct Cert{
        string cert_hash;
        bool exist; // Determine whether the certificate exists
    }

    //The index is the account address
    mapping (address => Cert) certs;

    //CA account
    mapping (address => bool) accounts;

    constructor(){
        accounts[0xC676f75f9542f624AACbE99D0118e945B97041AB] = true;
    }

    //CA account is required to operate
    modifier onlyCA(){
        require(accounts[msg.sender] == true, "Permission Denied");
        _;
    }

    //The certificate is required to exist
    modifier certExist(address addr){
        require(certs[addr].exist == true, "Certificate does not exist");
        _;
    }

    function store(address addr, string memory cert_hash) public onlyCA {
        require(certs[addr].exist != true, "The certificate already exists");
        certs[addr].cert_hash = cert_hash;
        certs[addr].exist = true;
    }

    function query(address addr) public view certExist(addr) returns(string memory){
        return certs[addr].cert_hash;
    }

    function revoke(address addr, string memory cert_hash) public onlyCA certExist(addr){
        certs[addr].cert_hash = cert_hash;
        certs[addr].exist = false;
    }
}

