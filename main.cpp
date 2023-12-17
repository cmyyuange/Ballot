#include <iostream>
#include <cstdlib>
#include <thread>
#include <chrono>
#include <fstream>
#include <vector>
#include <curl/curl.h>
#include "cryptopp/integer.h"
#include "cryptopp/osrng.h"
#include <cryptopp/cryptlib.h>
#include <cryptopp/nbtheory.h>
#include "cryptopp/modarith.h"
#include "cryptopp/dh.h"
#include <jsoncpp/json/json.h>
#include <sstream>

using namespace std;
using namespace CryptoPP;
using namespace chrono;

struct Elgamal {
    Integer C1;
    Integer C2;
};

struct Key {
    Integer SK;
    Integer PK;
};

class SigStruct {
private:
    std::string sig;
    std::string param_info;

public:
    void setSig(const std::string& _sig) {
        sig = _sig;
    }

    void setParam(const std::string& _param) {
        param_info = _param;
    }

    string getSig() {
        return sig;
    }

    string getParam() {
        return param_info;
    }
};

class RetCode {
public:
    static const int SUCCESS = 200;
};

void jump();
void main_UI();
void vote_UI();
void thank_UI();
void generate_key();
void de_crypto();
void log_UI();
void logo();
void logo_top();
void logo_bottom();
void logo_key();
void logo_key_change();
string http_post(const string& url, const string& post_fields);
string smart_contract(string function, string key);
string json_parse(string json, string key);
Json::Value genParamMap(const std::string& method);
std::string getParam(const Json::Value& paramMap);
Integer elgamal_mul(Integer a, Integer b);
Elgamal elgamal_en_crypto(Integer weight, Integer pk);
Integer blinding(Integer r, Integer c1, Integer c2);
Integer blind_sig(Integer m);
Integer unblinding(Integer r, Integer bs);
std::string httpPostJson(const std::string& url, const std::string& param);
Key elgamal_key_gen();
Integer middle_result(Integer c1, Integer sk);
bool linkableRingSig(SigStruct& ringSigObj, const std::string& message, const std::string& ringName, int memberPos, int ringSize);

string smart_contract_json(const string& json);

vector<Integer> global_elgamal_sk;
vector<Integer> global_elgamal_pk;
vector<string> global_ring_sk;
vector<string> global_ring_pk;
Integer global_elgamal_sum_pk;
Integer w[3][3] = {{6, 0, -6},{1, 0, -1},{3, 0, -3}};
string ring_param = "ewogICAiZyIgOiAiMi4iLAogICAicCIgOiAiMTUyMzg2NDA0NDk1OTcwOTEwNzMxMTM1NTU1ODk5MDI5MDA0MDQ5ODI1MTE4ODUwMDY4NjYyODA1ODA2ODYzMDYxMTYwNDQ3NTI4MzUxMzk1MjEzNDI0OTg5MDAwODAxOTMwNzAzNTgyNjk3MjQ3MDEyNjY1NTYwMDI3MTAyMjk5MjE4MzA2OTE1NDA0MDIzMjgzMTIxMzc4OTA0MjgzMTAwMDM5NjI4NjUwMTAyNTg4ODcwNjkyNDMxMzQ0MjU2MzIxODMzNzU0NDk0MjcxODUzNzU2MTk5Mzg2NzY2MzUyOTQyMDA1NTE3MDM1OTE2MDAyNDg4OTk1NzMyMjU1ODQyNDQwMDgxODU5OTMwNjgxNTk2NzAzODExMjYyMTMxMzMwMjQzOTA5NzMzNTQ1NjQzMjc5LiIsCiAgICJxIiA6ICI3NjE5MzIwMjI0Nzk4NTQ1NTM2NTU2Nzc3Nzk0OTUxNDUwMjAyNDkxMjU1OTQyNTAzNDMzMTQwMjkwMzQzMTUzMDU4MDIyMzc2NDE3NTY5NzYwNjcxMjQ5NDUwMDQwMDk2NTM1MTc5MTM0ODYyMzUwNjMzMjc4MDAxMzU1MTE0OTYwOTE1MzQ1NzcwMjAxMTY0MTU2MDY4OTQ1MjE0MTU1MDAxOTgxNDMyNTA1MTI5NDQzNTM0NjIxNTY3MjEyODE2MDkxNjg3NzI0NzEzNTkyNjg3ODA5OTY5MzM4MzE3NjQ3MTAwMjc1ODUxNzk1ODAwMTI0NDQ5Nzg2NjEyNzkyMTIyMDA0MDkyOTk2NTM0MDc5ODM1MTkwNTYzMTA2NTY2NTEyMTk1NDg2Njc3MjgyMTYzOS4iCn0K";
string ring_url = "http://8.219.52.112:8005";
Integer R = 7;
int name_index = 0;

int main() {
    Integer sk_1("88608026444183617139169995899996207538805597046393178301952610018762014521985432465548027912660413374846410415098997879838601235973426220343570526671530653412633910013938217968221008285051944852085961210935958657490126255372093302358946259324515022301421018745385583611450620990714918147358594707040469001042");
    Integer pk_1("49010587101150663284743303358021925256715165282005131266433104999809646175848289386446703523443117894129884009181804142860601164485006585426971292423828458700892747359132958123754982931963417971545097140373847955137108430932633390151828573669367025790121448171726633625841659595440492928306924556705742210700");
    Integer sk_2("37119806321684045288616588052363078038463028244704581199707440279972589147302103110738505447417864605704855650875674691007334735378791363923482062822361491793200189803973544038947952237998065016663473242060633774304439896502175313876589156918583386920517904405422944109254008631114127921521349464188269724797");
    Integer pk_2("123746030885021484763922292261713120000837392317996105715510801917929885149175674996262855743697618061005239592770595673252686160446717952974953554786872376930925435167756279546755463311856149539971647484658284972389267421174483810488714305107058985085498410207303972635955978995306532387967737823279237124936");
    Integer sk_3("432026258289771840039881970530514178139526248332544172311431235294566998412137221019087999913211013027622073020005866924843183601719539071112667589666884193581785207925098843794801856469173832850585928530856267548342977371021462903192814270860672564984488380481400496352814746295564207298534870360977147860");
    Integer pk_3("68721011612053531262231552633182107623979616589792761881803006155475325762215170829871663649129325922449626707510229755206645180810759393272813995954445233350891846578057158664584249869632930705620769354263606958057598640680184112602932270937808041474500362828208573598744012999990110982256974651746846731644");
    global_elgamal_sk.push_back(sk_1);
    global_elgamal_sk.push_back(sk_2);
    global_elgamal_sk.push_back(sk_3);
    global_elgamal_pk.push_back(pk_1);
    global_elgamal_pk.push_back(pk_2);
    global_elgamal_pk.push_back(pk_3);
    global_ring_sk.push_back("ewogICAicG9zIiA6ICIwIiwKICAgInBya194IiA6ICIxNTc5Mjk0OTQ3MjEwMzg3Nzc4ODc4MzgyNDM0OTM1NzA5Mzk4NjgzNDk1Mzc5ODY5OTc5MDE5MDg0NTYzMTQ3Mjc0NzkwMjY3NDAxNjk0NDE1MjM5MTI2NjE0NzI1Mjk0NTI0MDExODQzMzMzMDI0OTcyODkyNzM2MzgxMzg4MzM3ODY5ODcyODU4NTcwNDkzMDIxMTk4MDcwMjcwMDU1NTY2ODUwMzMwOTkyNzk3MTcxNDU5MTk5NTI1OTg0MjgwNjk0MTAyMTgwODkyNzYyMjExNDczMDIxMTM4NzU3MDMwNTcxMDcxMTM5ODMzNTQ0NDc0MTYwNTAyMDAxMzY4MzQ1OTQwNjU2NTU3NjkyODY2MDc3NDg4MjM5MjYwMzExNTEyMTg3OTkwOTcwNDY5MTcwMC4iCn0K");
    global_ring_sk.push_back("ewogICAicG9zIiA6ICIxIiwKICAgInBya194IiA6ICI3MDU0Mzg5MzAxOTE0ODM4NzgxNjgwOTk4MzgxNzQ5Nzc5MTk4MDg1MTQzNTMzOTE5MDcwODU0NDU4MTc0NTYzOTU5MTcxODAwMTMyMzUwODM3OTc4OTY5MzU0OTU2OTY1NTE4MDc0MTg4OTc3NzcyMzA5NjUwNzY1NjQwMDc0NjQ4OTU4NDUwMzYwOTQ5NTU2NDgxMDcxNDczNjY5NDM0MDUxNzgxNTI0NjIzNjc0NTM2Nzg5NDExMjQ5MDk5MTc2OTY2MzY2NTA1NTAzODM5MzQ1NjA5MjUyNjIxMzI4MTAyMDc3OTU1MDk4NjQwMDY5NDUxNzk4MzU3NzgzMjA0MTM3Nzg4MjM3OTE1MDk5MjcwOTYzMzY4MDIzNDk5MjE0NzA0MjY5ODcxODkyNTUzNjcyMi4iCn0K");
    global_ring_sk.push_back("ewogICAicG9zIiA6ICIyIiwKICAgInBya194IiA6ICIyNzc2NzcxMjU4MDU2MDg1ODA4MjAxMzI4MTczNjQ1NTA5MDA4NjkxMTk1NjU1NzYzNjY3MzEwNjU3NTIxODAwODYyNzM5NDQ2NTc5MTYwNzM4NjI0NTI4MjMyNDQ2ODQ2MTU0MDgzODYwNzc4OTIyMTE0NDA0NzcwNzQwNDM1OTMzMDM4OTg2NTQ2MTQ1ODgxODA0MDc5ODgwMjE3NzM4MDkyNjEzNTkyMTMzODMxMjgxOTA4MDQyNzQ2OTM3MTI1MjYxOTQ4MDg3MTU2NDM2MzY3MzQ5Njc1MzYxNjQzODI2NzY2MTM5MzAzNDE2MDc0MDUwMzgzODQyMTg4NjQ1MzMyODQ5MzA5NDQ0NjEzNDI1MDc5NzExOTAzODE0NDU3NDQzMzI1NjAwNjU0MTQ0MzU4MC4iCn0K");
    global_ring_pk.push_back("NDE5NzExNDIyNDg3Mzc4ODc3MDk1MjgyMTgxMDc3MjUyNDM4Mjk4NDU0NTEwOTgwNjQ3NzgzOTU3MTk0ODgzMzc5MjI5NDg5MzYyMzA4MzA5Mzg0MzcwODc1MDQxMzk5NTY2MjY0NTEzNTgzNDIzNzYwOTExMDk5OTE0MjUwMzQyMDI3NDA2MDgxOTgxNDA3MzQyMTE1ODA1OTA4ODc3Nzk1MDE1OTE2MTYyMTYzOTI5NTc3MzUxMDYwNTk0Mzc1NzA1MDA0ODEwODcyNjA3NDIzMDgyOTkwNjc2MTg3MjA1ODM1NzIxNjg1NzAzNjc4ODU5NDk0Njg0ODQxNjM2NzQyOTcxMjIzNDkxMTE4NzI3MjQ2ODI4MTU5NDgzMjAxNzk5MzQ4NzQxNzcwNzk4OTk5NjIu");
    global_ring_pk.push_back("MTE4OTEyNjkwMzY4MzAwNzkzNDE1ODY0MTQ4NjkwMjc3MjU1MzcwMzQyNzI2NTkzMTIwNTY1OTgxODQzNjAwOTYyNTU0MjY0OTY2NDI2NDczOTY2NDMzMTE1MDYxNjA4MTc5NDUyOTM3ODE4NDY3NTE4MTMwNDI4NTQ4MTIzMTEwMjU0MDc2MDgzNjM3NTI1NTk5OTkzMTQ0MDM4NTU1MDgxNjU3ODQxNjQ0MDA1NTgyMzM3NTE0Mjg1MjgyODM2NTUyODc2OTE0NjU5MTM3ODY3OTY2MTkyOTc3ODk3Mzk0MTE1ODc0MDI3MTYyMDM2NjU3ODY5NzEwNTU5MTc1NjE0NjA4MDYxODYzODM4NTYwMzMxNTE0MDk4Nzk5OTg2NDkyMDQzMjQzMDY2NzI1MDAxMDkyLg==");
    global_ring_pk.push_back("NDYwNjUwNDI5ODA0ODIxMTk3MDc1MjU2MjM1NzgwMjUxMjc2MjY5NzE3MDAzOTUxMDY5MDEwNzA4NDc1MTYwMDk2MzM4MjI5MTM4MzQ3MzM1Mzc5MzU1MjgwNTQ3NDE2Mzk2MzkxNzQ5MDQwOTY3MjMzNDIxMzE4OTg0MDE5Njg0MjEwMjk4MTg0MjI2MDc0MzEyMDIyOTg0MDI0MDA0MTM3ODYzMDkyOTQ5OTk1NjkxMjI2MjcyOTk0MjMwMTYzNjkzNDMxMDA0Nzc0MzE5NDk2NzcyMDYwMzcwMTk1NzM3MDA0Nzg1Nzk1OTkwNTM3NzI5NDcyNzIwMjUyMDA2NDQzODczMjIyNzczNjAzMTMzMzg5NTAzNjMwODMzMDQxNjU5NjQ4NTc3NDE1Mzk1NjQ0ODAu");
    jump();
    main_UI();
    SigStruct ringSigObj;
    while (true) {
        int number;
        cin >> number;
        switch (number) {
            case 1:
                jump();
                log_UI();
                jump();
                main_UI();
                break;
            case 2:
                jump();
                generate_key();
                jump();
                main_UI();
                break;
            case 3:
                jump();
                vote_UI();
                jump();
                main_UI();
                break;
            case 4:
                jump();
                de_crypto();
                jump();
                main_UI();
                break;
            case 0:
                jump();
                thank_UI();
                exit(0);
        }
    }
}

void main_UI() {
    string tap = "                                                        ";
    for (int i = 0; i < 5; ++i) {
        cout << endl;
    }
    cout << tap << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << endl;
    cout << tap << "|                                                           |" << endl;
    cout << tap << "|                           ______                          |" << endl;
    cout << tap << "|                          //    \\\\                         |" << endl;
    cout << tap << "|                         ||      ||                        |" << endl;
    cout << tap << "|                       __||______||__                      |" << endl;
    cout << tap << "|                      |     ____     |                     |" << endl;
    cout << tap << "|                      |    |    |    |                     |" << endl;
    cout << tap << "|                      |     \\  /     |                     |" << endl;
    cout << tap << "|                      \\     |__|     /                     |" << endl;
    cout << tap << "|                       \\____________/                      |" << endl;
    for (int i = 0; i < 2; ++i) {
        cout << tap << "|                                                           |" << endl;
    }
    cout << tap << "|                       (1)  log in                         |" << endl;
    cout << tap << "|                                                           |" << endl;
    cout << tap << "|                       (2)   Key                           |" << endl;
    cout << tap << "|                                                           |" << endl;
    cout << tap << "|                       (3)   Vote                          |" << endl;
    cout << tap << "|                                                           |" << endl;
    cout << tap << "|                       (4) Decryption                      |" << endl;
    cout << tap << "|                                                           |" << endl;
    cout << tap << "|                       (0)   Exit                          |" << endl;
    for (int i = 0; i < 2; ++i) {
        cout << tap << "|                                                           |" << endl;
    }
    cout << tap << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << endl;
    for (int i = 0; i < 5; ++i) {
        cout << endl;
    }
}

void generate_key() {
    Integer mul = 1;
    for (int i = 0; i < global_elgamal_pk.size(); ++i) {
        mul = elgamal_mul(mul, global_elgamal_pk[i]);
    }
    global_elgamal_sum_pk = mul;
    string tap = "                                                        ";
    logo_key_change();
    logo_key();
    cout << endl;
    cout << tap << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << endl;
    for (int i = 0; i < 2; ++i) {
        cout << tap << "|                                                           |" << endl;
    }
    cout << tap << "|                        Successful!                        |" << endl;
    for (int i = 0; i < 2; ++i) {
        cout << tap << "|                                                           |" << endl;
    }
    cout << tap << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << endl;
    for (int i = 0; i < 10; ++i) {
        cout << endl;
    }
    this_thread::sleep_for(chrono::seconds(3));
}

void vote_UI() {
    int candidate;
    Integer weight;
    string tap = "                                                        ";
    cout << tap << "*************************************************************" << endl;
    for (int i = 0; i < 2; ++i) {
        cout << endl;
    }
    cout << tap << "                      (1) candidate 0                      " << endl;
    cout << endl;
    cout << tap << "                      (2) candidate 1                      " << endl;
    cout << endl;
    cout << tap << "                      (0)    back                          " << endl;
    for (int i = 0; i < 2; ++i) {
        cout << endl;
    }
    cout << tap << "*************************************************************" << endl;
    for (int i = 0; i < 10; ++i) {
        cout << endl;
    }
    int number;
    cin >> number;
    //TODO:记录投票人
    switch (number) {
        case 1:
            candidate = 0;
            break;
        case 2:
            candidate = 1;
            break;
        case 0:
            return;
    }
    jump();
    cout << tap << "*************************************************************" << endl;
    for (int i = 0; i < 2; ++i) {
        cout << endl;
    }
    cout << tap << "                      (1) weight " << w[name_index][0] << "           " << endl;
    cout << endl;
    cout << tap << "                      (2) weight " << w[name_index][1] << "          " << endl;
    cout << endl;
    cout << tap << "                      (3) weight " << w[name_index][2] << "         " << endl;
    cout << endl;
    cout << tap << "                        (0) back                        " << endl;
    for (int i = 0; i < 2; ++i) {
        cout << endl;
    }
    cout << tap << "*************************************************************" << endl;
    for (int i = 0; i < 10; ++i) {
        cout << endl;
    }
    cin >> number;
    //TODO:记录权重
    switch (number) {
        case 1:
            weight = w[0][0];
            break;
        case 2:
            weight = w[0][1];
            break;
        case 3:
            weight = w[0][2];
            break;
        case 0:
            return;
    }
    //TODO:加密操作
    Elgamal cipher = elgamal_en_crypto(weight, global_elgamal_sum_pk);
    cout << "c1: " << cipher.C1 << endl;
    cout << "c2: " << cipher.C2 << endl;
    //TODO:盲化操作
    Integer bm = blinding(R, cipher.C1, cipher.C2);
    //TODO:盲签名
    Integer bs = blind_sig(bm);
    //TODO:解盲
    Integer s = unblinding(R, bs);
    //TODO:环签名
    SigStruct ringSigObj;
    linkableRingSig(ringSigObj,IntToString(s),"hacker",0,3);
    string ring_sig = ringSigObj.getSig();
    //TODO:调用智能合约
    string json = "{\n"
                  "        \"groupId\": \"1\",\n"
                  "        \"signUserId\": \"727bf95b839a441283c2ad1a1349896d\",\n"
                  "        \"contractName\": \"SimpleBallot\",\n"
                  "        \"contractPath\": \"/\",\n"
                  "        \"version\": \"\",\n"
                  "        \"funcName\": \"vote\",\n"
                  "        \"funcParam\":[魔,\"牛\",\"马\",\"蛇\",\"神\",\"妖\"],\n"
                  "\t\"contractAddress\": \"0xec1057facdbdb18434a0b0b67b52a066980c8d4e\",\n"
                  "\t\"contractAbi\":[{\"inputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"candidataInformations\",\"type\":\"string\"}],\"name\":\"addCandidate\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"voterInformations\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"voterPublicKeys\",\"type\":\"string\"}],\"name\":\"addVoter\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"decrypto\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"endBallot\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getBallotEndTime\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getBallotInformation\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getBallotStartTime\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getBallotState\",\"outputs\":[{\"internalType\":\"enum SimpleBallot.BallotState\",\"name\":\"\",\"type\":\"uint8\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"getCandidate\",\"outputs\":[{\"components\":[{\"internalType\":\"string\",\"name\":\"candidateInformation\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"C1\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"C2\",\"type\":\"string\"},{\"internalType\":\"string[]\",\"name\":\"MiddleResult\",\"type\":\"string[]\"},{\"internalType\":\"string\",\"name\":\"voteCount\",\"type\":\"string\"}],\"internalType\":\"struct SimpleBallot.Candidate\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"getCandidate_C1\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"getCandidate_voteCount\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getOwner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"getVoter\",\"outputs\":[{\"components\":[{\"internalType\":\"string\",\"name\":\"voterInformation\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"voterPublicKey\",\"type\":\"string\"}],\"internalType\":\"struct SimpleBallot.Voter\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getWinner\",\"outputs\":[{\"components\":[{\"internalType\":\"string\",\"name\":\"candidateInformation\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"C1\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"C2\",\"type\":\"string\"},{\"internalType\":\"string[]\",\"name\":\"MiddleResult\",\"type\":\"string[]\"},{\"internalType\":\"string\",\"name\":\"voteCount\",\"type\":\"string\"}],\"internalType\":\"struct SimpleBallot.Candidate\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"middleResult\",\"type\":\"string\"},{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"sendMiddleResult\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"startBallot\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"state\",\"outputs\":[{\"internalType\":\"enum SimpleBallot.BallotState\",\"name\":\"\",\"type\":\"uint8\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"},{\"internalType\":\"string\",\"name\":\"ringSig\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"paramInfo\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"c1\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"c2\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"blindSig\",\"type\":\"string\"}],\"name\":\"vote\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}],\n"
                  "  \"useAes\": false,\n"
                  "        \"useCns\": false,\n"
                  "        \"cnsName\": \"\"\n"
                  "}";
    //[魔,"牛","马","蛇","神","妖"]
    string word = "魔";
    json.replace(json.find("魔"), word.length(), to_string(candidate));
    json.replace(json.find("牛"), word.length(), ring_sig);
    json.replace(json.find("马"), word.length(), ring_param);
    json.replace(json.find("蛇"), word.length(), IntToString(cipher.C1));
    json.replace(json.find("神"), word.length(), IntToString(cipher.C2));
    json.replace(json.find("妖"), 2, IntToString(s));
    cout << json << endl;
    smart_contract_json(json);
    jump();
    logo_top();
    cout << endl;
    cout << endl;
    logo_bottom();
    for (int i = 0; i < 15; ++i) {
        cout << endl;
    }
    this_thread::sleep_for(chrono::milliseconds(1000));
    jump();
    logo_top();
    cout << endl;
    logo_bottom();
    for (int i = 0; i < 15; ++i) {
        cout << endl;
    }
    this_thread::sleep_for(chrono::milliseconds(1000));
    jump();
    logo_top();
    logo_bottom();
    for (int i = 0; i < 15; ++i) {
        cout << endl;
    }
    this_thread::sleep_for(chrono::milliseconds(1000));
    jump();
    logo();
    for (int i = 0; i < 15; ++i) {
        cout << endl;
    }
    this_thread::sleep_for(chrono::milliseconds(1000));
    jump();
    logo();
    cout << tap << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << endl;
    for (int i = 0; i < 2; ++i) {
        cout << tap << "|                                                           |" << endl;
    }
    cout << tap << "|                        Successful!                        |" << endl;
    for (int i = 0; i < 2; ++i) {
        cout << tap << "|                                                           |" << endl;
    }
    cout << tap << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << endl;
    for (int i = 0; i < 10; ++i) {
        cout << endl;
    }
    this_thread::sleep_for(chrono::seconds(3));
}

string smart_contract_json(const string& json) {
    std::string url = "http://1.12.64.174:5002/WeBASE-Front/trans/handleWithSign";

    std::string response = http_post(url, json);
    //std::cout << "Response: \n" << response << std::endl;

    return response;
}

void de_crypto() {
    string json_0 = "{\n"
                  "        \"groupId\": \"1\",\n"
                  "        \"signUserId\": \"727bf95b839a441283c2ad1a1349896d\",\n"
                  "        \"contractName\": \"SimpleBallot\",\n"
                  "        \"contractPath\": \"/\",\n"
                  "        \"version\": \"\",\n"
                  "        \"funcName\": \"getCandidate_C1\",\n"
                  "        \"funcParam\":[0],\n"
                  "\t\"contractAddress\": \"0xec1057facdbdb18434a0b0b67b52a066980c8d4e\",\n"
                  "\t\"contractAbi\":[{\"inputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"candidataInformations\",\"type\":\"string\"}],\"name\":\"addCandidate\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"voterInformations\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"voterPublicKeys\",\"type\":\"string\"}],\"name\":\"addVoter\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"decrypto\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"endBallot\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getBallotEndTime\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getBallotInformation\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getBallotStartTime\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getBallotState\",\"outputs\":[{\"internalType\":\"enum SimpleBallot.BallotState\",\"name\":\"\",\"type\":\"uint8\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"getCandidate\",\"outputs\":[{\"components\":[{\"internalType\":\"string\",\"name\":\"candidateInformation\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"C1\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"C2\",\"type\":\"string\"},{\"internalType\":\"string[]\",\"name\":\"MiddleResult\",\"type\":\"string[]\"},{\"internalType\":\"string\",\"name\":\"voteCount\",\"type\":\"string\"}],\"internalType\":\"struct SimpleBallot.Candidate\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"getCandidate_C1\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"getCandidate_voteCount\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getOwner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"getVoter\",\"outputs\":[{\"components\":[{\"internalType\":\"string\",\"name\":\"voterInformation\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"voterPublicKey\",\"type\":\"string\"}],\"internalType\":\"struct SimpleBallot.Voter\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getWinner\",\"outputs\":[{\"components\":[{\"internalType\":\"string\",\"name\":\"candidateInformation\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"C1\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"C2\",\"type\":\"string\"},{\"internalType\":\"string[]\",\"name\":\"MiddleResult\",\"type\":\"string[]\"},{\"internalType\":\"string\",\"name\":\"voteCount\",\"type\":\"string\"}],\"internalType\":\"struct SimpleBallot.Candidate\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"middleResult\",\"type\":\"string\"},{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"sendMiddleResult\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"startBallot\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"state\",\"outputs\":[{\"internalType\":\"enum SimpleBallot.BallotState\",\"name\":\"\",\"type\":\"uint8\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"},{\"internalType\":\"string\",\"name\":\"ringSig\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"paramInfo\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"c1\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"c2\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"blindSig\",\"type\":\"string\"}],\"name\":\"vote\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}],\n"
                  "  \"useAes\": false,\n"
                  "        \"useCns\": false,\n"
                  "        \"cnsName\": \"\"\n"
                  "}";
    //TODO:从智能合约获取C1
    string c1_0 = smart_contract_json(json_0);
    string json_1 = "{\n"
                  "        \"groupId\": \"1\",\n"
                  "        \"signUserId\": \"727bf95b839a441283c2ad1a1349896d\",\n"
                  "        \"contractName\": \"SimpleBallot\",\n"
                  "        \"contractPath\": \"/\",\n"
                  "        \"version\": \"\",\n"
                  "        \"funcName\": \"getCandidate_C1\",\n"
                  "        \"funcParam\":[1],\n"
                  "\t\"contractAddress\": \"0xec1057facdbdb18434a0b0b67b52a066980c8d4e\",\n"
                  "\t\"contractAbi\":[{\"inputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"candidataInformations\",\"type\":\"string\"}],\"name\":\"addCandidate\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"voterInformations\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"voterPublicKeys\",\"type\":\"string\"}],\"name\":\"addVoter\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"decrypto\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"endBallot\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getBallotEndTime\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getBallotInformation\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getBallotStartTime\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getBallotState\",\"outputs\":[{\"internalType\":\"enum SimpleBallot.BallotState\",\"name\":\"\",\"type\":\"uint8\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"getCandidate\",\"outputs\":[{\"components\":[{\"internalType\":\"string\",\"name\":\"candidateInformation\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"C1\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"C2\",\"type\":\"string\"},{\"internalType\":\"string[]\",\"name\":\"MiddleResult\",\"type\":\"string[]\"},{\"internalType\":\"string\",\"name\":\"voteCount\",\"type\":\"string\"}],\"internalType\":\"struct SimpleBallot.Candidate\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"getCandidate_C1\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"getCandidate_voteCount\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getOwner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"getVoter\",\"outputs\":[{\"components\":[{\"internalType\":\"string\",\"name\":\"voterInformation\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"voterPublicKey\",\"type\":\"string\"}],\"internalType\":\"struct SimpleBallot.Voter\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getWinner\",\"outputs\":[{\"components\":[{\"internalType\":\"string\",\"name\":\"candidateInformation\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"C1\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"C2\",\"type\":\"string\"},{\"internalType\":\"string[]\",\"name\":\"MiddleResult\",\"type\":\"string[]\"},{\"internalType\":\"string\",\"name\":\"voteCount\",\"type\":\"string\"}],\"internalType\":\"struct SimpleBallot.Candidate\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"middleResult\",\"type\":\"string\"},{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"sendMiddleResult\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"startBallot\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"state\",\"outputs\":[{\"internalType\":\"enum SimpleBallot.BallotState\",\"name\":\"\",\"type\":\"uint8\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"},{\"internalType\":\"string\",\"name\":\"ringSig\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"paramInfo\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"c1\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"c2\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"blindSig\",\"type\":\"string\"}],\"name\":\"vote\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}],\n"
                  "  \"useAes\": false,\n"
                  "        \"useCns\": false,\n"
                  "        \"cnsName\": \"\"\n"
                  "}";
    string c1_1 = smart_contract_json(json_1);
    cout << "c1_0: " << c1_0 << endl;
    cout << "c1_1: " << c1_1 << endl;
    //TODO:计算中间结果
    Integer C1_0(c1_0.c_str());
    Integer C1_1(c1_1.c_str());
    Integer middle_1 = middle_result(C1_0,global_elgamal_sk[2]);
    Integer middle_2 = middle_result(C1_1,global_elgamal_sk[2]);
    //TODO:调用智能合约发送中间结果
    string json_2 = "{\n"
                    "        \"groupId\": \"1\",\n"
                    "        \"signUserId\": \"727bf95b839a441283c2ad1a1349896d\",\n"
                    "        \"contractName\": \"SimpleBallot\",\n"
                    "        \"contractPath\": \"/\",\n"
                    "        \"version\": \"\",\n"
                    "        \"funcName\": \"sendMiddleResult\",\n"
                    "        \"funcParam\":[牛, 0],\n"
                    "\t\"contractAddress\": \"0xec1057facdbdb18434a0b0b67b52a066980c8d4e\",\n"
                    "\t\"contractAbi\":[{\"inputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"candidataInformations\",\"type\":\"string\"}],\"name\":\"addCandidate\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"voterInformations\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"voterPublicKeys\",\"type\":\"string\"}],\"name\":\"addVoter\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"decrypto\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"endBallot\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getBallotEndTime\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getBallotInformation\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getBallotStartTime\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getBallotState\",\"outputs\":[{\"internalType\":\"enum SimpleBallot.BallotState\",\"name\":\"\",\"type\":\"uint8\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"getCandidate\",\"outputs\":[{\"components\":[{\"internalType\":\"string\",\"name\":\"candidateInformation\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"C1\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"C2\",\"type\":\"string\"},{\"internalType\":\"string[]\",\"name\":\"MiddleResult\",\"type\":\"string[]\"},{\"internalType\":\"string\",\"name\":\"voteCount\",\"type\":\"string\"}],\"internalType\":\"struct SimpleBallot.Candidate\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"getCandidate_C1\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"getCandidate_voteCount\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getOwner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"getVoter\",\"outputs\":[{\"components\":[{\"internalType\":\"string\",\"name\":\"voterInformation\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"voterPublicKey\",\"type\":\"string\"}],\"internalType\":\"struct SimpleBallot.Voter\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getWinner\",\"outputs\":[{\"components\":[{\"internalType\":\"string\",\"name\":\"candidateInformation\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"C1\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"C2\",\"type\":\"string\"},{\"internalType\":\"string[]\",\"name\":\"MiddleResult\",\"type\":\"string[]\"},{\"internalType\":\"string\",\"name\":\"voteCount\",\"type\":\"string\"}],\"internalType\":\"struct SimpleBallot.Candidate\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"middleResult\",\"type\":\"string\"},{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"sendMiddleResult\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"startBallot\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"state\",\"outputs\":[{\"internalType\":\"enum SimpleBallot.BallotState\",\"name\":\"\",\"type\":\"uint8\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"},{\"internalType\":\"string\",\"name\":\"ringSig\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"paramInfo\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"c1\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"c2\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"blindSig\",\"type\":\"string\"}],\"name\":\"vote\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}],\n"
                    "  \"useAes\": false,\n"
                    "        \"useCns\": false,\n"
                    "        \"cnsName\": \"\"\n"
                    "}";
    json_2.replace(json_2.find("牛"), 2, IntToString(middle_1));
    smart_contract_json(json_2);
    string json_3 = "{\n"
                    "        \"groupId\": \"1\",\n"
                    "        \"signUserId\": \"727bf95b839a441283c2ad1a1349896d\",\n"
                    "        \"contractName\": \"SimpleBallot\",\n"
                    "        \"contractPath\": \"/\",\n"
                    "        \"version\": \"\",\n"
                    "        \"funcName\": \"sendMiddleResult\",\n"
                    "        \"funcParam\":[马, 1],\n"
                    "\t\"contractAddress\": \"0xec1057facdbdb18434a0b0b67b52a066980c8d4e\",\n"
                    "\t\"contractAbi\":[{\"inputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"candidataInformations\",\"type\":\"string\"}],\"name\":\"addCandidate\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"voterInformations\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"voterPublicKeys\",\"type\":\"string\"}],\"name\":\"addVoter\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"decrypto\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"endBallot\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getBallotEndTime\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getBallotInformation\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getBallotStartTime\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getBallotState\",\"outputs\":[{\"internalType\":\"enum SimpleBallot.BallotState\",\"name\":\"\",\"type\":\"uint8\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"getCandidate\",\"outputs\":[{\"components\":[{\"internalType\":\"string\",\"name\":\"candidateInformation\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"C1\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"C2\",\"type\":\"string\"},{\"internalType\":\"string[]\",\"name\":\"MiddleResult\",\"type\":\"string[]\"},{\"internalType\":\"string\",\"name\":\"voteCount\",\"type\":\"string\"}],\"internalType\":\"struct SimpleBallot.Candidate\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"getCandidate_C1\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"getCandidate_voteCount\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getOwner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"getVoter\",\"outputs\":[{\"components\":[{\"internalType\":\"string\",\"name\":\"voterInformation\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"voterPublicKey\",\"type\":\"string\"}],\"internalType\":\"struct SimpleBallot.Voter\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getWinner\",\"outputs\":[{\"components\":[{\"internalType\":\"string\",\"name\":\"candidateInformation\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"C1\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"C2\",\"type\":\"string\"},{\"internalType\":\"string[]\",\"name\":\"MiddleResult\",\"type\":\"string[]\"},{\"internalType\":\"string\",\"name\":\"voteCount\",\"type\":\"string\"}],\"internalType\":\"struct SimpleBallot.Candidate\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"middleResult\",\"type\":\"string\"},{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"sendMiddleResult\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"startBallot\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"state\",\"outputs\":[{\"internalType\":\"enum SimpleBallot.BallotState\",\"name\":\"\",\"type\":\"uint8\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"},{\"internalType\":\"string\",\"name\":\"ringSig\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"paramInfo\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"c1\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"c2\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"blindSig\",\"type\":\"string\"}],\"name\":\"vote\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}],\n"
                    "  \"useAes\": false,\n"
                    "        \"useCns\": false,\n"
                    "        \"cnsName\": \"\"\n"
                    "}";
    json_3.replace(json_3.find("马"), 2, IntToString(middle_2));
    smart_contract_json(json_3);
    string tap = "                                                        ";
    jump();
    logo();
    for (int i = 0; i < 15; ++i) {
        cout << endl;
    }
    this_thread::sleep_for(chrono::milliseconds(1000));
    jump();
    logo_top();
    logo_bottom();
    for (int i = 0; i < 15; ++i) {
        cout << endl;
    }
    this_thread::sleep_for(chrono::milliseconds(1000));
    jump();
    logo_top();
    cout << endl;
    logo_bottom();
    for (int i = 0; i < 15; ++i) {
        cout << endl;
    }
    this_thread::sleep_for(chrono::milliseconds(1000));
    jump();
    logo_top();
    cout << endl;
    cout << endl;
    logo_bottom();
    for (int i = 0; i < 15; ++i) {
        cout << endl;
    }
    this_thread::sleep_for(chrono::milliseconds(1000));
    jump();
    logo_top();
    cout << endl;
    cout << endl;
    logo_bottom();
    cout << tap << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << endl;
    for (int i = 0; i < 2; ++i) {
        cout << tap << "|                                                           |" << endl;
    }
    cout << tap << "|                        Successful!                        |" << endl;
    for (int i = 0; i < 2; ++i) {
        cout << tap << "|                                                           |" << endl;
    }
    cout << tap << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << endl;
    for (int i = 0; i < 10; ++i) {
        cout << endl;
    }
    this_thread::sleep_for(chrono::seconds(3));
}

void log_UI() {
    string tap = "                                                        ";
    cout << tap << "*************************************************************" << endl;
    for (int i = 0; i < 3; ++i) {
        cout << endl;
    }
    cout << tap << "                         (1) user A                        " << endl;
    cout << endl;
    cout << tap << "                         (2) user B                           " << endl;
    cout << endl;
    cout << tap << "                         (3) user C                           " << endl;
    for (int i = 0; i < 3; ++i) {
        cout << endl;
    }
    cout << tap << "*************************************************************" << endl;
    for (int i = 0; i < 10; ++i) {
        cout << endl;
    }
    int number;
    cin >> number;
    switch (number) {
        case 1:
            name_index = 0;
            break;
        case 2:
            name_index = 1;
            break;
        case 3:
            name_index = 2;
            break;
    }
    jump();
    vector<string> name = {"user A","user B","user C"};
    cout << tap << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << endl;
    for (int i = 0; i < 2; ++i) {
        cout << tap << "|                                                           |" << endl;
    }
    cout << tap << "|                       "<< name[name_index] << " log in                       |" << endl;
    for (int i = 0; i < 2; ++i) {
        cout << tap << "|                                                           |" << endl;
    }
    cout << tap << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << endl;
    for (int i = 0; i < 15; ++i) {
        cout << endl;
    }
    this_thread::sleep_for(chrono::seconds(3));
}

void thank_UI() {
    logo();
    string tap = "                                                        ";
    cout << tap << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << endl;
    for (int i = 0; i < 2; ++i) {
        cout << tap << "|                                                           |" << endl;
    }
    cout << tap << "|               Thank you very much for using               |" << endl;
    for (int i = 0; i < 2; ++i) {
        cout << tap << "|                                                           |" << endl;
    }
    cout << tap << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << endl;
    for (int i = 0; i < 10; ++i) {
        cout << endl;
    }
}

void logo() {
    string tap = "                                                        ";
    cout << tap << "                            ______                           " << endl;
    cout << tap << "                           //    \\\\                          " << endl;
    cout << tap << "                          ||      ||                         " << endl;
    cout << tap << "                        __||______||__                       " << endl;
    cout << tap << "                       |     ____     |                      " << endl;
    cout << tap << "                       |    |    |    |                      " << endl;
    cout << tap << "                       |     \\  /     |                      " << endl;
    cout << tap << "                       \\     |__|     /                      " << endl;
    cout << tap << "                        \\____________/                       " << endl;
    cout << endl;
}

void logo_top() {
    string tap = "                                                        ";
    cout << tap << "                            ______                           " << endl;
    cout << tap << "                           //    \\\\                          " << endl;
    cout << tap << "                          ||      ||                         " << endl;
    cout << tap << "                          ||      ||                       " << endl;
}

void logo_bottom() {
    string tap = "                                                        ";
    cout << tap << "                        ______________                       " << endl;
    cout << tap << "                       |     ____     |                      " << endl;
    cout << tap << "                       |    |    |    |                      " << endl;
    cout << tap << "                       |     \\  /     |                      " << endl;
    cout << tap << "                       \\     |__|     /                      " << endl;
    cout << tap << "                        \\____________/                       " << endl;
    cout << endl;
}

void logo_key() {
    string tap = "                                                        ";
    cout << tap << "                               /\\                  " << endl;
    cout << tap << "                              |  |_            " << endl;
    cout << tap << "                              |   _|             " << endl;
    cout << tap << "                              |  |_           " << endl;
    cout << tap << "                              |   _|           " << endl;
    cout << tap << "                              |  |             " << endl;
    cout << tap << "                              |  |              " << endl;
    cout << tap << "                             _|__|_          " << endl;
    cout << tap << "                            / ____ \\                " << endl;
    cout << tap << "                           / /    \\ \\             " << endl;
    cout << tap << "                          | |      | |              " << endl;
    cout << tap << "                          | |      | |       " << endl;
    cout << tap << "                           \\ \\____/ /          " << endl;
    cout << tap << "                            \\______/          " << endl;
}

void logo_key_change() {
    string tap = "                                                        ";
    for (int i = 0; i < 14; ++i) {
        if (i >= 13) {cout << tap << "                               /\\                  " << endl;}
        if (i >= 12) {cout << tap << "                              |  |_            " << endl;}
        if (i >= 11) {cout << tap << "                              |   _|             " << endl;}
        if (i >= 10) {cout << tap << "                              |  |_           " << endl;}
        if (i >= 9) {cout << tap << "                              |   _|           " << endl;}
        if (i >= 8) {cout << tap << "                              |  |             " << endl;}
        if (i >= 7) {cout << tap << "                              |  |              " << endl;}
        if (i >= 6) {cout << tap << "                             _|__|_          " << endl;}
        if (i >= 5) {cout << tap << "                            / ____ \\                " << endl;}
        if (i >= 4) {cout << tap << "                           / /    \\ \\             " << endl;}
        if (i >= 3) {cout << tap << "                          | |      | |              " << endl;}
        if (i >= 2) {cout << tap << "                          | |      | |       " << endl;}
        if (i >= 1) {cout << tap << "                           \\ \\____/ /          " << endl;}
        if (i >= 0) {cout << tap << "                            \\______/          " << endl;}
        for (int j = 0; j < 15; ++j) {
            cout << endl;
        }
        this_thread::sleep_for(chrono::milliseconds(300));
        jump();
    }
}

void jump() {
    for (int i = 0; i < 50; ++i) {
        cout << endl;
    }
}

/************************************************************************************************************************************************************************************************************************************/

bool linkableRingSig(SigStruct& ringSigObj, const std::string& message, const std::string& ringName, int memberPos, int ringSize) {
    Json::Value paramMap = genParamMap("linkable_ring_sig");;
    Json::Value subParamMap;

    subParamMap["ring_name"] = ringName;
    subParamMap["message"] = message;
    subParamMap["id"] = std::to_string(memberPos);
    subParamMap["ring_size"] = std::to_string(ringSize);
    paramMap["params"] = subParamMap;

    const std::string ringParam = getParam(paramMap);

    std::string jsonRet = httpPostJson(ring_url, ringParam); // 替换为你的 URL
    Json::CharReaderBuilder readerBuilder;
    Json::Value jsonObj;
    std::string errs;
    std::istringstream iss(jsonRet);
    if (Json::parseFromStream(readerBuilder, iss, &jsonObj, &errs)) {
        const Json::Value& result = jsonObj["result"];
        if (!result.isNull() && result["ret_code"].asInt() == 0) {
            ringSigObj.setSig(result["sig"].asString());
            ringSigObj.setParam(result["param_info"].asString());
            return true;
        }
    }
    return false;
}

Json::Value genParamMap(const std::string& method) {
    Json::Value paramMap;
    paramMap["method"] = method;
    paramMap["id"] = 1;
    paramMap["jsonrpc"] = "2.0";
    return paramMap;
}

std::string getParam(const Json::Value& paramMap) {
    return Json::FastWriter().write(paramMap);
}

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

//size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
//    userp->append((char*)contents, size * nmemb);
//    return size * nmemb;
//}

std::string httpPostJson(const std::string& url, const std::string& jsonData) {
    CURL* curl = curl_easy_init();
    std::string readBuffer;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << '\n';
        }
        curl_easy_cleanup(curl);
    }
    return readBuffer;
}

//static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
//    ((string*)userp)->append((char*)contents, size * nmemb);
//    return size * nmemb;
//}

string http_post(const string& url, const string& post_fields) {
    CURL* curl = curl_easy_init();
    string readBuffer;
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    if(curl) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    return readBuffer;
}

string smart_contract(string function, string key) {
//    ifstream file(function);
//    Json::Value root;
//    Json::CharReaderBuilder builder;
//    std::string errs;
//
//    if (!Json::parseFromStream(builder, file, &root, &errs)) {
//        std::cerr << "Error parsing JSON: " << errs << std::endl;
//    }
//    Json::StreamWriterBuilder writerBuilder;
//    std::string output = Json::writeString(writerBuilder, root);
//
//    std::string url = "http://1.12.64.174:5002/WeBASE-Front/trans/handleWithSign";
//    std::string post_fields = output;
//    //std::string post_fields = "{\"groupId\": \"1\",\"signUserId\": \"727bf95b839a441283c2ad1a1349896d\",\"contractName\": \"SimpleBallot\",\"contractPath\": \"/\",\"version\": \"\",\"funcName\": \"getOwner\",\"funcParam\": [],\"contractAddress\": \"0x7c9ca0396aeeabf66462d17b5dbed2db0882a68e\",\"contractAbi\":[{\"inputs\":[],\"name\":\"getOwner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"}],\"useAes\": false,\"useCns\": false,\"cnsName\": \"\"}";
//
//    std::string response = http_post(url, post_fields);
//    std::cout << "Response: \n" << response << std::endl;
//
//    return json_parse(response, key);
    return "";
}

string json_parse(string json, string key) {
    Json::Value root;
    Json::CharReaderBuilder builder;
    Json::CharReader* reader = builder.newCharReader();

    std::string jsonString = json;
    std::string errors;
    bool parsingSuccessful = reader->parse(jsonString.c_str(), jsonString.c_str() + jsonString.size(), &root, &errors);
    delete reader;
    if (!parsingSuccessful) {
        std::cerr << "Error parsing JSON: " << errors << std::endl;
    }
    if (root.isMember(key)) {
        std::string result = root[key].asString();
        std::cout << key << ": " << result << std::endl;
        return result;
    } else {
        std::cout << "field not found." << std::endl;
    }
}

/************************************************************************************************************************************************************************************************************************************/

Integer elgamal_mul(Integer a, Integer b) {
    const Integer P("137667678801418493501099391114533684830163187054170336532698477154953895389678113432585844374671165207853966093676774345313260178925119177152949112050782979385063011345783723569751829421917190488703487112628294112534652799029303117614405960247759063618318170611036245425457412534838334623565025785567248020807");
    return (a * b) % P;
}

Elgamal elgamal_en_crypto(Integer weight, Integer pk) {
    const Integer a = 2;
    const Integer G = 2;
    const Integer P("137667678801418493501099391114533684830163187054170336532698477154953895389678113432585844374671165207853966093676774345313260178925119177152949112050782979385063011345783723569751829421917190488703487112628294112534652799029303117614405960247759063618318170611036245425457412534838334623565025785567248020807");
    AutoSeededRandomPool rng;

    Integer r;
    r.Randomize(rng,Integer::Zero(),P - Integer::One());
    Integer c1 = ModularExponentiation(G, r, P);
    ModularArithmetic modArithmetic_elgamal(P);
    Integer c2;
    if (weight.IsPositive())
    {
        c2 = (ModularExponentiation(pk, r, P) * ModularExponentiation(a, weight, P)) % P;
    }
    else if (weight.IsNegative())
    {
        c2 = (ModularExponentiation(pk, r, P) * modArithmetic_elgamal.MultiplicativeInverse(ModularExponentiation(a,-weight,P))) % P;
    }
    else
    {
        c2 = ModularExponentiation(pk, r, P) * Integer::One();
    }
    Elgamal elgamal;
    elgamal.C1 = c1;
    elgamal.C2 = c2;
    return elgamal;
}

Integer blinding(Integer r, Integer c1, Integer c2) {
    const Integer n("139971197205585545224505747804314383999314819537111861431151893639932898331380036134595558214878826864747794583841709332931421758028145704213979848792166063896884277176579670344251481893124885177040004019592444795172661889287023870873302974581821529563180569558330171859190174724928710535079423863401951413677");
    const Integer d("20583999589056697827133198206516821176369826402516450210463513770578367401673534725675817384541003950698205085859074901901679670298256721207938213057671476504261096884638864079359646050128168509777016449283309422819149962353713517179925511480058868409230968344596849904550929451344986858079407450612718387703");
    const Integer e("17");
    const Integer P("137667678801418493501099391114533684830163187054170336532698477154953895389678113432585844374671165207853966093676774345313260178925119177152949112050782979385063011345783723569751829421917190488703487112628294112534652799029303117614405960247759063618318170611036245425457412534838334623565025785567248020807");

    Integer sum = (c1 + c2) % P;
    Integer bm = (sum * ModularExponentiation(r, e, n)) % n;
    return bm;
}

Integer blind_sig(Integer m) {
    const Integer n("139971197205585545224505747804314383999314819537111861431151893639932898331380036134595558214878826864747794583841709332931421758028145704213979848792166063896884277176579670344251481893124885177040004019592444795172661889287023870873302974581821529563180569558330171859190174724928710535079423863401951413677");
    const Integer d("20583999589056697827133198206516821176369826402516450210463513770578367401673534725675817384541003950698205085859074901901679670298256721207938213057671476504261096884638864079359646050128168509777016449283309422819149962353713517179925511480058868409230968344596849904550929451344986858079407450612718387703");
    const Integer P("137667678801418493501099391114533684830163187054170336532698477154953895389678113432585844374671165207853966093676774345313260178925119177152949112050782979385063011345783723569751829421917190488703487112628294112534652799029303117614405960247759063618318170611036245425457412534838334623565025785567248020807");

    Integer bs = ModularExponentiation(m, d, n);
    return bs;
}

Integer unblinding(Integer r, Integer bs) {
    const Integer n("139971197205585545224505747804314383999314819537111861431151893639932898331380036134595558214878826864747794583841709332931421758028145704213979848792166063896884277176579670344251481893124885177040004019592444795172661889287023870873302974581821529563180569558330171859190174724928710535079423863401951413677");
    const Integer P("137667678801418493501099391114533684830163187054170336532698477154953895389678113432585844374671165207853966093676774345313260178925119177152949112050782979385063011345783723569751829421917190488703487112628294112534652799029303117614405960247759063618318170611036245425457412534838334623565025785567248020807");
    ModularArithmetic modArithmetic_rsa(n);

    Integer s = (bs * modArithmetic_rsa.MultiplicativeInverse(r)) % n;
    return s;
}

Key elgamal_key_gen() {
    const Integer G = 2;
    const Integer P("137667678801418493501099391114533684830163187054170336532698477154953895389678113432585844374671165207853966093676774345313260178925119177152949112050782979385063011345783723569751829421917190488703487112628294112534652799029303117614405960247759063618318170611036245425457412534838334623565025785567248020807");
    AutoSeededRandomPool rng;

    Integer sk;
    sk.Randomize(rng,Integer::Zero(),P - Integer::One());
    Integer pk = ModularExponentiation(G, sk, P);
    Key key;
    key.SK = sk;
    key.PK = pk;
    return key;
}

Integer middle_result(Integer c1, Integer sk) {
    const Integer P("137667678801418493501099391114533684830163187054170336532698477154953895389678113432585844374671165207853966093676774345313260178925119177152949112050782979385063011345783723569751829421917190488703487112628294112534652799029303117614405960247759063618318170611036245425457412534838334623565025785567248020807");
    ModularArithmetic modArithmetic_elgamal(P);

    Integer middle = modArithmetic_elgamal.MultiplicativeInverse(ModularExponentiation(c1,sk,P));
    return middle;
}