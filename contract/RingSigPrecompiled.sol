pragma solidity >=0.4.25;

abstract contract RingSigPrecompiled{
     function ringSigVerify(string memory signature, string memory message, string memory paramInfo) public virtual returns(bool);
}