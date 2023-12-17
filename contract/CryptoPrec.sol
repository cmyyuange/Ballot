pragma solidity >=0.4.25;

abstract contract CryptoPrec{
    function blindVerify(string memory a,string memory b,string memory c) public virtual returns(bool);
    function elgamalMul(string memory a,string memory b,string memory c) public virtual returns(string memory);
    function elgamalDecrypt(string memory a,string memory b,string memory c) public virtual returns(string memory);
}