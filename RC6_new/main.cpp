#include <iostream>
#include <fstream>
#include <sstream>
#include <getopt.h>
#include <string>
#include <stdlib.h>
#include <ctime>

#include "util.h"

using namespace std;

//const string default_key="e9d0fc76d5c1a4fd93eb8bf9f4dea208";
const string default_key = ".d,A?gba,FgBeE?,dD.fcf?c?F,.eCAc";
const string challenge_cipher = "F.d?e,,fadbec.gDFEDABcCAA,dE?ce.AaCEgBb,Bg?BA?ceaAbfBbCBagDgcfbD";
//const unsigned char translate_table[16]={'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
const unsigned char translate_table[16]={'A','B','C','D','E','F','a','b','c','d','e','f','g',',','.','?'};
//const unsigned char candidate[16]={'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
const unsigned char candidate[16]={'A','B','C','D','E','F','a','b','c','d','e','f','g',',','.','?'};
const char* short_option="ge:d:k:";
struct option long_option[]={
        {"generate", 0, NULL, 'g'},
        {"encrypt", 1, NULL, 'e'},
        {"decrypt", 1, NULL, 'd'},
        {"key", 1, NULL, 'K'},
        {0, 0, 0, 0}
};

void generate_key();
void print_ciphertext(unsigned char* ciphertext);
unsigned char translate_ciphertext(unsigned char temp_char);
bool not_legal(unsigned char temp);
void print_plaintext(unsigned char* plaintext);
bool wrong_char(unsigned char temp);


int main(int argc, char* argv[])
{
    std::ios::sync_with_stdio(false);
    std::cin.tie(0);
    bool generate=false;
    bool encrypt=false;
    bool decrypt=false;
    bool has_key=false;
    int c=0;
    string filename;
    string message;
    while(!((c=getopt_long(argc, argv, short_option, long_option, NULL))==-1))
    {
        switch(c)
        {
            case 'g':
            {
                generate = true;
                break;
            }
            case 'e':
            {
                encrypt = true;
                message = optarg;
                break;
            }
            case 'd':
            {
                decrypt = true;
                message = optarg;
                break;
            }
            case 'K':
            {
                has_key = true;
                filename = optarg;
                break;
            }
            default:
                break;
        }
    }

    //generate key
    if(generate)
    {
        generate_key();
        return 0;
    }

    //get key
    unsigned char temp_char;
    unsigned char k[16];
    stringstream istringstream;
    int index=0;
    ifstream keyfile;
    if(has_key) {
        keyfile.open(filename.c_str(), ios::in);
        if (!keyfile) {
            //cout<<"Fail to open file"<<endl;
            has_key = false;
        } else {
            while (keyfile >> temp_char) {
                temp_char = translate_ciphertext(temp_char);
                k[index] = temp_char;
                k[index] = k[index] << 4;
                if (keyfile >> temp_char) {
                    temp_char = translate_ciphertext(temp_char);
                    k[index] = k[index] + temp_char;
                }
                index++;
                if (index == 16)
                    break;
            }
            if (index < 16) {
                for (int i = index; i < 16; i++)
                    k[i] = 0;
            }
            keyfile.close();
        }
    }
    if(!has_key)
    {
        istringstream << default_key;
        while(istringstream >> temp_char)
        {
            temp_char=translate_ciphertext(temp_char);
            k[index]=temp_char;
            k[index]=k[index]<<4;
            if(istringstream >> temp_char)
            {
                temp_char=translate_ciphertext(temp_char);
                k[index]=k[index]+temp_char;
            }
            index++;
            if(index==16)
                break;
        }
    }
    istringstream.clear();

    int block_number;
    if(message.length()%16==0)
        block_number=message.length()/16;
    else
        block_number=(message.length()+16)/16;

    int block_index=0;
    unsigned char (*plaintext)[16]=new unsigned char [block_number+10][16];
    unsigned char (*ciphertext)[16]=new unsigned char [block_number+10][16];
    unsigned char (*ciphertext_set)[16] = new unsigned char [block_number+10][16];
    unsigned char (*plaintext_set)[16] = new unsigned char [block_number+10][16];
    unsigned char cipher_last[16] = {0xff,0x44,0x55,0xed,0xaa,0xaf,0x0e,0xd7,0x08,0x8f,0x4c,0xcc,0xba,0xb4,0x3c,0x56};
    unsigned char cipher_temp[16];
    unsigned char plain_temp[16];


    //encrypt
    if(encrypt)
    {
        istringstream << message;
        while(istringstream >> temp_char)
        {
            if(not_legal(temp_char))
                continue;
            index=0;
            plaintext[block_index][index]=temp_char;
            index++;
            while(istringstream >> temp_char)
            {
                if(not_legal(temp_char))
                    continue;
                plaintext[block_index][index]=temp_char;
                index++;
                if(index==16)
                    break;
            }
            if(index < 16)
            {
                for(int i=index; i<16; i++)
                    plaintext[block_index][i] = '-';
            }
            for(int j = 0; j < 16; j++){
                plaintext[block_index][j] = plaintext[block_index][j]^cipher_last[j];
            }
            encryption(plaintext[block_index], ciphertext[block_index], k);
            for(int j = 0; j < 16; j++){
                cipher_last[j] = ciphertext[block_index][j];
            }
            block_index++;
        }
        //output
        unsigned char cipher_last2[16] = {0xff,0x44,0x55,0xed,0xaa,0xaf,0x0e,0xd7,0x08,0x8f,0x4c,0xcc,0xba,0xb4,0x3c,0x56};
        for(int i = block_number-1; i >=0; i --){
            for(int j = 0; j < 16; j ++){
                ciphertext[i][j] = ciphertext[i][j] ^ cipher_last2[j];
            }
            encryption(ciphertext[i], cipher_temp, k);
            for(int j = 0; j < 16; j ++){
                cipher_last2[j] = cipher_temp[j];
            }
            for(int j = 0; j < 16; j++){
                ciphertext_set[i][j] = cipher_temp[j];
            }
        }
        unsigned char cipher_last4[16] = {0xff,0x44,0x55,0xed,0xaa,0xaf,0x0e,0xd7,0x08,0x8f,0x4c,0xcc,0xba,0xb4,0x3c,0x56};
        for(int i = 0; i < block_number; i ++){
            for(int j = 0; j < 16; j ++){
                ciphertext_set[i][j] = ciphertext_set[i][j] ^ cipher_last4[j];
            }
            encryption(ciphertext_set[i], cipher_temp, k);
            for(int j = 0; j < 16; j ++){
                cipher_last4[j] = cipher_temp[j];
            }
            for(int j = 0; j < 16; j++){
                ciphertext[i][j] = cipher_temp[j];
            }
        }

        unsigned char cipher_last6[16] = {0xff,0x44,0x55,0xed,0xaa,0xaf,0x0e,0xd7,0x08,0x8f,0x4c,0xcc,0xba,0xb4,0x3c,0x56};
        for(int i = block_number - 1; i >=0; i --){
            for(int j = 0; j < 16; j ++){
                ciphertext[i][j] = ciphertext[i][j] ^ cipher_last6[j];
            }
            encryption(ciphertext[i], cipher_temp, k);
            for(int j = 0; j < 16; j ++){
                cipher_last6[j] = cipher_temp[j];
            }
            for(int j = 0; j < 16; j++){
                ciphertext_set[block_number - 1 - i][j] = cipher_temp[j];
            }
            print_ciphertext(cipher_temp);
        }
        cout<<endl;


        delete[] plaintext;
        delete[] ciphertext;
        delete[] ciphertext_set;
        delete[] plaintext_set;
        return 0;
    }

    unsigned char cipher_last1[16] = {0xff,0x44,0x55,0xed,0xaa,0xaf,0x0e,0xd7,0x08,0x8f,0x4c,0xcc,0xba,0xb4,0x3c,0x56};
    bool wrong = false;
    //decrypt
    if(decrypt)
    {
        if(message == challenge_cipher){
            cout<<"cheater: it is forbidden to decrypt the challenge ciphertext"<<endl;
            return 0;
        }
        if(message.length()%32==0)
            block_number=message.length()/32;
        else
            block_number=(message.length()+32)/32;
        istringstream << message;
        while(istringstream >> temp_char)
        {
            if(!wrong) {
                wrong = wrong_char(temp_char);
            }
            temp_char=translate_ciphertext(temp_char);
            index = 0;
            temp_char=temp_char<<4;
            ciphertext[block_index][index]=temp_char;
            if(istringstream >> temp_char)
            {
                if(!wrong) {
                    wrong = wrong_char(temp_char);
                }
                temp_char=translate_ciphertext(temp_char);
                ciphertext[block_index][index]=temp_char^ciphertext[block_index][index];
            }
            else{
                for(int i=index+1; i<16; i++)
                    ciphertext[block_index][i]=0;
                if(wrong){
                    for(int i = 0; i < 16; i ++){
                        ciphertext[block_index][i] += k[i];
                    }
                }
                decryption(plaintext[block_index], ciphertext[block_index], k);
                for(int i = 0; i < 16; i++){
                    plaintext[block_index][i] = plaintext[block_index][i]^cipher_last1[i];
                }
                for(int i = 0; i < 16; i++){
                    cipher_last1[i] = ciphertext[block_index][i];
                }
                block_index++;
                break;
            }
            index++;
            while(istringstream >> temp_char)
            {
                if(!wrong) {
                    wrong = wrong_char(temp_char);
                }
                temp_char=translate_ciphertext(temp_char);
                temp_char=temp_char<<4;
                ciphertext[block_index][index]=temp_char;
                if(istringstream >> temp_char)
                {
                    if(!wrong) {
                        wrong = wrong_char(temp_char);
                    }
                    temp_char=translate_ciphertext(temp_char);
                    ciphertext[block_index][index]=temp_char^ciphertext[block_index][index];
                }
                else{
                    for(int i=index+1; i<16; i++)
                        ciphertext[block_index][i]=0;
                    if(wrong){
                        for(int i = 0; i < 16; i ++){
                            ciphertext[block_index][i] += k[i];
                        }
                    }
                    decryption(plaintext[block_index], ciphertext[block_index], k);
                    for(int i = 0; i < 16; i++){
                        plaintext[block_index][i] = plaintext[block_index][i]^cipher_last1[i];
                    }
                    for(int i = 0; i < 16; i++){
                        cipher_last1[i] = ciphertext[block_index][i];
                    }
                    block_index++;
                    break;
                }
                index++;
                if(index==16)
                    break;

            }
            if(index<16)
            {
                for(int i=index; i<16; i++)
                    ciphertext[block_index][i]=0;
            }
            if(wrong){
                for(int i = 0; i < 16; i ++){
                    ciphertext[block_index][i] += k[i];
                }
            }
            decryption(plaintext[block_index], ciphertext[block_index], k);
            for(int i = 0; i < 16; i++){
                plaintext[block_index][i] = plaintext[block_index][i]^cipher_last1[i];
            }
            for(int i = 0; i < 16; i++){
                cipher_last1[i] = ciphertext[block_index][i];
            }
            block_index++;
        }
        unsigned char cipher_last3[16] = {0xff,0x44,0x55,0xed,0xaa,0xaf,0x0e,0xd7,0x08,0x8f,0x4c,0xcc,0xba,0xb4,0x3c,0x56};
        for(int i = block_number-1; i >=0; i --){
            decryption(plain_temp, plaintext[i],k);
            for(int j = 0; j < 16; j ++){
                plain_temp[j] = plain_temp[j] ^ cipher_last3[j];
            }
            for(int j = 0; j < 16; j ++){
                cipher_last3[j] = plaintext[i][j];
            }
            for(int j = 0; j < 16; j ++){
                plaintext_set[i][j] = plain_temp[j];
            }
        }
        unsigned char cipher_last5[16] = {0xff,0x44,0x55,0xed,0xaa,0xaf,0x0e,0xd7,0x08,0x8f,0x4c,0xcc,0xba,0xb4,0x3c,0x56};
        for(int i = 0; i < block_number; i ++){
            decryption(plain_temp, plaintext_set[i],k);
            for(int j = 0; j < 16; j ++){
                plain_temp[j] = plain_temp[j] ^ cipher_last5[j];
            }
            for(int j = 0; j < 16; j ++){
                cipher_last5[j] = plaintext_set[i][j];
            }
            for(int j = 0; j < 16; j ++){
                plaintext[block_number - 1 - i][j] = plain_temp[j];
            }
        }
        unsigned char cipher_last7[16] = {0xff,0x44,0x55,0xed,0xaa,0xaf,0x0e,0xd7,0x08,0x8f,0x4c,0xcc,0xba,0xb4,0x3c,0x56};
        for(int i = 0; i < block_number; i ++){
            decryption(plain_temp, plaintext[i],k);
            for(int j = 0; j < 16; j ++){
                plain_temp[j] = plain_temp[j] ^ cipher_last7[j];
            }
            for(int j = 0; j < 16; j ++){
                cipher_last7[j] = plaintext[i][j];
            }
            for(int j = 0; j < 16; j ++){
                plaintext_set[i][j] = plain_temp[j];
            }
            print_plaintext(plain_temp);
        }
        cout<<endl;

        delete[] plaintext;
        delete[] ciphertext;
        delete[] ciphertext_set;
        delete[] plaintext_set;
        return 0;
    }
    return 0;
}


void generate_key()
{
    srand(time(NULL));
    for(int i=0; i<32; i++)
        cout<<candidate[rand()%16];
    cout<<endl;
}

void print_ciphertext(unsigned char* ciphertext)
{
    for(int i=0; i<16; i++)
    {
        cout<<translate_table[(ciphertext[i]-ciphertext[i]%16)>>4];
        cout<<translate_table[ciphertext[i]%16];
    }
}

unsigned char translate_ciphertext(unsigned char temp_char)
{
    switch(temp_char)
    {
        case 'A':
            return 0;
        case 'B':
            return 1;
        case 'C':
            return 2;
        case 'D':
            return 3;
        case 'E':
            return 4;
        case 'F':
            return 5;
        case 'a':
            return 6;
        case 'b':
            return 7;
        case 'c':
            return 8;
        case 'd':
            return 9;
        case 'e':
            return 10;
        case 'f':
            return 11;
        case 'g':
            return 12;
        case ',':
            return 13;
        case '.':
            return 14;
        case '?':
            return 15;
        default:
            return 0;
    }
}

bool not_legal(unsigned char temp)
{
    if((temp>='a' && temp <='z') || (temp>='0' && temp<='9') || (temp>='A' && temp<='Z') || (temp==',')||(temp=='.')||(temp==';')||(temp=='?')||(temp=='!')||(temp=='(')||(temp==')'))
        return false;
    else
        return true;
}

bool wrong_char(unsigned char temp){
    if((temp >= 'a' && temp <='g') || (temp >= 'A' && temp <='F') || temp ==',' || temp == '?' || temp == '.')
    //if((temp>='a' && temp <='f') || (temp>='0' && temp<='9'))
        return false;
    else
        return true;
}

void print_plaintext(unsigned char* plaintext)
{
    for(int i=0; i<16; i++)
    {
        if(!not_legal(plaintext[i]))
            cout<<plaintext[i];
        else if(plaintext[i] != '-')
            cout<<'?';
    }
}