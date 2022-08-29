// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.9.0;

contract Au_CA{

    struct Cert{
        string cert_hash;
        bool exist; // Determine whether the certificate exists
    }

    //The index is a concatenated string of authorized address and authorized address
    mapping (string => Cert) certs;

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
    modifier certExist(string memory id){
        require(certs[id].exist == true, "Certificate does not exist");
        _;
    }

    function store(string memory id, string memory cert_hash) public onlyCA {
        require(certs[id].exist != true, "The certificate already exists");
        certs[id].cert_hash = cert_hash;
        certs[id].exist = true;
    }

    function query(string memory id) public view certExist(id) returns(string memory){
        return certs[id].cert_hash;
    }

    function revoke(string memory id, string memory cert_hash) public onlyCA certExist(id){
        certs[id].cert_hash = cert_hash;
        certs[id].exist = false;
    }
}
