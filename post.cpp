#include <iostream>
#include <string>
#include <curl/curl.h>
#include "cryptopp/integer.h"
#include "cryptopp/osrng.h"
#include "cryptopp/nbtheory.h"
#include "cryptopp/modarith.h"
#include "cryptopp/dh.h"
#include <jsoncpp/json/json.h>
#include <fstream>

using namespace std;
using namespace CryptoPP;
using namespace chrono;

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

std::string http_post(const std::string& url, const std::string& post_fields) {
    CURL* curl = curl_easy_init();
    std::string readBuffer;
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

int main() {

    //ifstream file("decrypto.json");
    ifstream file("vote_0.json");

    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errs;

    // 使用jsoncpp的解析器来解析JSON文件内容
    if (!Json::parseFromStream(builder, file, &root, &errs)) {
        std::cerr << "Error parsing JSON: " << errs << std::endl;
        return 1;
    }
    Json::StreamWriterBuilder writerBuilder;
    std::string output = Json::writeString(writerBuilder, root);

    std::string url = "http://1.12.64.174:5002/WeBASE-Front/trans/handleWithSign";
    std::string post_fields = output;
    //std::string post_fields = "{\"groupId\": \"1\",\"signUserId\": \"727bf95b839a441283c2ad1a1349896d\",\"contractName\": \"SimpleBallot\",\"contractPath\": \"/\",\"version\": \"\",\"funcName\": \"getOwner\",\"funcParam\": [],\"contractAddress\": \"0x7c9ca0396aeeabf66462d17b5dbed2db0882a68e\",\"contractAbi\":[{\"inputs\":[],\"name\":\"getOwner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"}],\"useAes\": false,\"useCns\": false,\"cnsName\": \"\"}";

    auto start = chrono::high_resolution_clock::now();
    std::string response = http_post(url, post_fields);
    auto end = chrono::high_resolution_clock::now();
    cout << "所需要时间: " << (duration_cast<microseconds>(end - start).count()) << "us" << endl;
    std::cout << "Response: \n" << response << std::endl;

    return 0;
}
