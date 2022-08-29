const Hash_SC = artifacts.require("Hash_SC");
const Id_CA = artifacts.require("Id_CA");
const Au_CA = artifacts.require("Au_CA");


module.exports = function (deployer) {
  deployer.deploy(Hash_SC);
  deployer.deploy(Id_CA);
  deployer.deploy(Au_CA);
};
