pragma solidity >=0.6.10;
pragma experimental ABIEncoderV2;

import "./CryptoPrec.sol";
import "./RingSigPrecompiled.sol";

contract SimpleBallot {

    CryptoPrec crypto;
    RingSigPrecompiled ringSig;

    // 构造函数
    constructor() public {
    owner = msg.sender;
    ringSig = RingSigPrecompiled(0x5005);
    crypto = CryptoPrec(0x5555);
    }

    struct Candidate {
        string candidateInformation;
        string C1;
        string C2;
        string[] MiddleResult;
        string voteCount;
    }

    // 投票者数据结构
    struct Voter {
        string voterInformation;
        string voterPublicKey;
    }

    address private owner;
    enum BallotState {waitingToStart,inProgress,finish}

    // 初始化投票参数
    string ballotInformation = "第一个投票测试";
    uint startTime = 0;
    uint endTime = 0;
    BallotState public state = BallotState.waitingToStart;
    Candidate[] candidates;
    Voter[] voters;
    Candidate winner;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    function addCandidate(string memory candidataInformations) onlyOwner external {
        string[] memory str;
        Candidate memory candidate = Candidate(candidataInformations,"NOT","NOT",str,"NOT");
        candidates.push(candidate);
    }

    function addVoter(string memory voterInformations, string memory voterPublicKeys) onlyOwner external {
        Voter memory voter = Voter(voterInformations,voterPublicKeys);
        voters.push(voter);
    }

    function startBallot() onlyOwner external {
        require(state == BallotState.waitingToStart,"Ballot is started or finished!");
        state = BallotState.inProgress;
        startTime = block.timestamp;
    }

    function vote(uint index, string memory ringSig, string memory paramInfo, string memory c1, string memory c2 , string memory blindSig) external {
        require(state == BallotState.inProgress,"Ballot is not in progress!");
        require(ringVerify(ringSig, blindSig, paramInfo),"Ring Signature verification failed!");
        require(crypto.blindVerify(c1,c2,blindSig),"Blind Signature verification failed!");
        if (stringCompare(candidates[index].C1, "NOT")) {
            candidates[index].C1 = c1;
            candidates[index].C2 = c2;
        }else {
            candidates[index].C1 = crypto.elgamalMul(candidates[index].C1,c1,"");
            candidates[index].C2 = crypto.elgamalMul(candidates[index].C2,c2,"");
        }
    }

    function ringVerify(string memory signature, string memory message, string memory paramInfo) internal returns(bool){
        return ringSig.ringSigVerify(signature, message, paramInfo);
    }

    function endBallot() onlyOwner external {
        require(state == BallotState.inProgress,"Ballot is not inProgress!");
        state =  BallotState.finish;
        endTime = block.timestamp;
    }

    function sendMiddleResult(string memory middleResult, uint index) external {
        require(state == BallotState.finish,"Ballot is not finished!");
        candidates[index].MiddleResult.push(middleResult);
    }

    function decrypto() onlyOwner external  {
        require(state == BallotState.finish,"Ballot is not finished!");
        for (uint i = 0; i < candidates.length; i++)
        {
            if (candidates[i].MiddleResult.length == 0) {
                continue;
            }
            string memory C1_MUL = candidates[i].MiddleResult[0];
            for (uint j = 1; j < candidates[i].MiddleResult.length; j++){
                C1_MUL = crypto.elgamalMul(C1_MUL,candidates[i].MiddleResult[j],"");
            }
            string memory addLog = crypto.elgamalMul(candidates[i].C2,C1_MUL,"");
            candidates[i].voteCount = crypto.elgamalDecrypt(addLog,"","");
        }
        // uint max = 0;
        // for (uint i = 0; i < candidates.length; i++)
        // {
        //     if (stringToUint(candidates[i].voteCount) > max){
        //         max = stringToUint(candidates[i].voteCount);
        //         winner = candidates[i];
        //     }
        // }
    }

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    function stringCompare(string memory a, string memory b) internal pure returns (bool) {
        return (keccak256(abi.encode(a)) == keccak256(abi.encode(b)));
    }

    function stringToUint(string memory s) internal returns (uint) {
        bytes memory b = bytes(s);
        uint result = 0;
        for (uint i = 0; i < b.length; i++) {
            if (b[i] >= "0" && b[i] <= "9") {
                result = result * 10 + (uint(uint8(b[i])) - 48);
            }
        }
        return result;
    }

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    function getOwner() public view returns (address) {
        return owner;
    }

    function getWinner() public view returns (Candidate memory) {
        return winner;
    }

    function getBallotInformation() public view returns (string memory) {
        return ballotInformation;
    }

    function getCandidate(uint index) public view returns (Candidate memory) {
        return candidates[index];
    }

    function getCandidate_C1(uint index) public view returns (string memory) {
        return candidates[index].C1;
    }

    function getCandidate_voteCount(uint index) public view returns (string memory) {
        return candidates[index].voteCount;
    }

    function getVoter(uint index) public view returns (Voter memory) {
        return voters[index];
    }

    function getBallotStartTime() public view returns (uint) {
        return startTime;
    }

    function getBallotEndTime() public view returns (uint) {
        return endTime;
    }

    function getBallotState() public view returns (BallotState) {
        return state;
    }

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
}