#include <iostream>
#include <fstream>
#include <sstream>
#include <getopt.h>
#include <string>
#include <stdlib.h>
#include <ctime>

#include "util.h"

using namespace std;

const string default_key="f62b61116f5b791ccb966e0bc2461301";
const unsigned char translate_table[16]={'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
//const unsigned char candidate[69]={'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o' ,'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', ',', '.', ';', '?', '!', '(', ')'};
const unsigned char candidate[16]={'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

const char* short_option="ge:d:k:";
struct option long_option[]={
        {"generate", 0, NULL, 'g'},
        {"encrypt", 1, NULL, 'e'},
        {"decrypt", 1, NULL, 'd'},
        {"key", 1, NULL, 'k'},
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
            case 'k':
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
    if(has_key)
    {
        keyfile.open(filename.c_str(), ios::in);
        if(!keyfile)
        {
            cout<<"Fail to open file"<<endl;
            return -1;
        }
        keyfile >> filename;
        istringstream << filename;
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
        if(index<16)
        {
            for(int i=index; i<16; i++)
                k[i]=0;
        }
        keyfile.close();
        for(int i = 0; i < 16; i++){
            cout<<(int)k[i];
        }
        cout<<endl;
    }
    else
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
        for(int i = 0; i < 16; i++){
            cout<<(int)k[i];
        }
        cout<<endl;
    }
    istringstream.clear();


    int block_number;
    if(message.length()%16==0)
        block_number=message.length()/16;
    else
        block_number=(message.length()+16)/16;
    unsigned char* new_plaintext;
    unsigned char* new_ciphertext;
    int block_index=0;
    unsigned char (*plaintext)[16]=new unsigned char [block_number+10][16];
    unsigned char (*ciphertext)[16]=new unsigned char [block_number+10][16];
    unsigned char (*ciphertext_set)[16] = new unsigned char [block_number+10][16];
    unsigned char (*plaintext_set)[16] = new unsigned char [block_number+10][16];
    unsigned char cipher_last[16] = {0xff,0x44,0x55,0xed,0xaa,0xaf,0x0e,0xd7,0x08,0x8f,0x4c,0xcc,0xba,0xb4,0x3c,0x56};
    unsigned char* cipher_temp;
    unsigned char* plain_temp;

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
            new_ciphertext = encoder(plaintext[block_index], k);
            for(int i=0; i<16; i++)
            {
                ciphertext[block_index][i]=new_ciphertext[i];
                cipher_last[i] = new_ciphertext[i];
            }
            block_index++;
        }
        for(int i=0; i<block_number; i++)
            print_ciphertext(ciphertext[i]);
        cout<<endl;
        //output
        unsigned char cipher_last2[16] = {0xff,0x44,0x55,0xed,0xaa,0xaf,0x0e,0xd7,0x08,0x8f,0x4c,0xcc,0xba,0xb4,0x3c,0x56};
        //unsigned char** ciphertext_set[block_number+10][16];
        for(int i = block_number-1; i >=0; i --){
            for(int j = 0; j < 16; j ++){
                ciphertext[i][j] = ciphertext[i][j] ^ cipher_last2[j];
            }
            cipher_temp = encoder(ciphertext[i],k);
            for(int j = 0; j < 16; j ++)
                cipher_last2[j] = cipher_temp[j];
            for(int j = 0; j < 16; j++){
                ciphertext_set[i][j] = cipher_temp[j];
            }
            print_ciphertext(cipher_temp);
        }

        cout << endl;
        unsigned char cipher_last4[16] = {0xff,0x44,0x55,0xed,0xaa,0xaf,0x0e,0xd7,0x08,0x8f,0x4c,0xcc,0xba,0xb4,0x3c,0x56};
        //unsigned char** ciphertext_set[block_number+10][16];
        for(int i = 0; i < block_number; i ++){
            for(int j = 0; j < 16; j ++){
                ciphertext_set[i][j] = ciphertext_set[i][j] ^ cipher_last4[j];
            }
            cipher_temp = encoder(ciphertext_set[i],k);
            for(int j = 0; j < 16; j ++)
                cipher_last4[j] = cipher_temp[j];
            for(int j = 0; j < 16; j++){
                ciphertext[i][j] = cipher_temp[j];
            }
            print_ciphertext(cipher_temp);
        }
        cout<<endl;
        unsigned char cipher_last6[16] = {0xff,0x44,0x55,0xed,0xaa,0xaf,0x0e,0xd7,0x08,0x8f,0x4c,0xcc,0xba,0xb4,0x3c,0x56};
        //unsigned char** ciphertext_set[block_number+10][16];
        for(int i = block_index -1; i >= 0; i --){
            for(int j = 0; j < 16; j ++){
                ciphertext[i][j] = ciphertext[i][j] ^ cipher_last6[j];
            }
            cipher_temp = encoder(ciphertext[i],k);
            for(int j = 0; j < 16; j ++)
                cipher_last6[j] = cipher_temp[j];
            for(int j = 0; j < 16; j++){
                ciphertext_set[block_number - 1 - i][j] = cipher_temp[j];
            }
            print_ciphertext(cipher_temp);
        }
        /*for(int i = 0; i < block_number; i++ ){
            print_ciphertext(ciphertext_set[i]);
        }*/
        cout<<endl;
        /*for(int i=0; i<block_number; i++)
            print_ciphertext(ciphertext[i]);
        cout<<endl;*/

        delete[] plaintext;
        delete[] ciphertext;
        delete[] ciphertext_set;
        delete[] plaintext_set;
        return 0;
    }

    unsigned char cipher_last1[16] = {0xff,0x44,0x55,0xed,0xaa,0xaf,0x0e,0xd7,0x08,0x8f,0x4c,0xcc,0xba,0xb4,0x3c,0x56};
    //decrypt
    block_index = 0;
    bool wrong = false; //used to check whether wrong char appears(wrong char means the char not in the range 0-9 and a-f)
    if(decrypt)
    {
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
                new_plaintext =	decoder(ciphertext[block_index], k);
                //
                for(int i = 0; i < 16; i++){
                    new_plaintext[i] = new_plaintext[i]^cipher_last1[i];
                }
                for(int i = 0; i < 16; i++){
                    cipher_last1[i] = ciphertext[block_index][i];
                }
                //
                for(int i=0; i<16; i++)
                    plaintext[block_index][i]=new_plaintext[i];
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
                    new_plaintext = decoder(ciphertext[block_index], k);
                    for(int i = 0; i < 16; i++){
                        new_plaintext[i] = new_plaintext[i]^cipher_last1[i];
                    }
                    for(int i = 0; i < 16; i++){
                        cipher_last1[i] = ciphertext[block_index][i];
                    }
                    for(int i=0; i<16; i++)
                        plaintext[block_index][i]=new_plaintext[i];
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
            new_plaintext = decoder(ciphertext[block_index], k);
            for(int i = 0; i < 16; i++){
                new_plaintext[i] = new_plaintext[i]^cipher_last1[i];
            }
            for(int i = 0; i < 16; i++){
                cipher_last1[i] = ciphertext[block_index][i];
            }
            for(int i=0; i<16; i++)
                plaintext[block_index][i]=new_plaintext[i];
            block_index++;
        }
        for(int i=0; i<block_number; i++)
            print_ciphertext(plaintext[i]);
        cout<<endl;
        //output
        /*unsigned char cipher_last3[16] = {0xff,0x44,0x55,0xed,0xaa,0xaf,0x0e,0xd7,0x08,0x8f,0x4c,0xcc,0xba,0xb4,0x3c,0x56};
        for(int i = block_number-1; i >=0; i --){
            plain_temp = decoder(plaintext[i],k);
            for(int j = 0; j < 16; j ++){
                plain_temp[j] = plain_temp[j] ^ cipher_last3[j];
            }
            for(int j = 0; j < 16; j ++){
                cipher_last3[j] = plaintext[i][j];
            }
            print_plaintext(plain_temp);
        }
        cout<<endl;*/
        unsigned char cipher_last3[16] = {0xff,0x44,0x55,0xed,0xaa,0xaf,0x0e,0xd7,0x08,0x8f,0x4c,0xcc,0xba,0xb4,0x3c,0x56};
        //unsigned char** ciphertext_set[block_number+10][16];
        for(int i = block_number-1; i >=0; i --){
            plain_temp = decoder(plaintext[i],k);
            for(int j = 0; j < 16; j ++){
                plain_temp[j] = plain_temp[j] ^ cipher_last3[j];
            }
            for(int j = 0; j < 16; j ++){
                cipher_last3[j] = plaintext[i][j];
            }
            for(int j = 0; j < 16; j ++){
                plaintext_set[i][j] = plain_temp[j];
            }
            print_plaintext(plain_temp);
        }

        cout << endl;
        unsigned char cipher_last5[16] = {0xff,0x44,0x55,0xed,0xaa,0xaf,0x0e,0xd7,0x08,0x8f,0x4c,0xcc,0xba,0xb4,0x3c,0x56};
        //unsigned char** ciphertext_set[block_number+10][16];
        for(int i = 0; i < block_number; i ++){
            plain_temp = decoder(plaintext_set[i],k);
            for(int j = 0; j < 16; j ++){
                plain_temp[j] = plain_temp[j] ^ cipher_last5[j];
            }
            for(int j = 0; j < 16; j ++){
                cipher_last5[j] = plaintext_set[i][j];
            }
            for(int j = 0; j < 16; j ++){
                plaintext[block_number - 1 - i][j] = plain_temp[j];
            }
            print_plaintext(plain_temp);
        }
        cout<<endl;
        unsigned char cipher_last6[16] = {0xff,0x44,0x55,0xed,0xaa,0xaf,0x0e,0xd7,0x08,0x8f,0x4c,0xcc,0xba,0xb4,0x3c,0x56};
        //unsigned char** ciphertext_set[block_number+10][16];
        for(int i = 0; i < block_number; i ++){
            plain_temp = decoder(plaintext[i],k);
            for(int j = 0; j < 16; j ++){
                plain_temp[j] = plain_temp[j] ^ cipher_last6[j];
            }
            for(int j = 0; j < 16; j ++){
                cipher_last6[j] = plaintext[i][j];
            }
            for(int j = 0; j < 16; j ++){
                plaintext_set[block_number-1-i][j] = plain_temp[j];
            }
            print_plaintext(plain_temp);
        }
        cout<<endl;
        /*for(int i=0; i<block_number; i++)
            print_plaintext(plaintext[i]);
        cout<<endl;*/

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
        case '0':
            return 0;
        case '1':
            return 1;
        case '2':
            return 2;
        case '3':
            return 3;
        case '4':
            return 4;
        case '5':
            return 5;
        case '6':
            return 6;
        case '7':
            return 7;
        case '8':
            return 8;
        case '9':
            return 9;
        case 'a':
            return 10;
        case 'b':
            return 11;
        case 'c':
            return 12;
        case 'd':
            return 13;
        case 'e':
            return 14;
        case 'f':
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
    if((temp>='a' && temp <='f') || (temp>='0' && temp<='9'))
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
    }
}