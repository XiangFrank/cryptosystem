//
// Created by frank on 19-6-30.
//
#include "util.h"
#include <iostream>
using namespace std;

void generate_roundkey(const unsigned char s[16], unsigned int l[44]){
    unsigned int S[4] = {0,0,0,0};
    for(int i = 0; i < 4; i++){
        S[0] += (( s[i]) << (unsigned int)(24-8*i));
        S[1] += (( s[4+i]) << (unsigned int)(24-8*i));
        S[2] += (( s[8+i]) << (unsigned int)(24-8*i));
        S[3] += (( s[12+i]) << (unsigned int)(24-8*i));
    }
    unsigned int p = 0xb7e15163;
    unsigned int q = 0x9e3779b9;
    l[0] = p;
    for(int i = 1; i < 44; i++){
        l[i] = (l[i-1] + q) & 0xFFFFFFFF;
    }
    unsigned int a, b,temp;
    a = 0; b = 0;
    int j = 0;
    int i = 0;
    for(int k = 0; k < 132; k++){
        temp = l[i] + a + b;
        l[i] = left_rot(temp, 3);
        a = l[i];
        temp = S[j] + a + b;
        S[j] = left_rot(temp, (a+b));
        b = S[j];
        i = (i + 1)%44;
        j = (j + 1)%4;
    }
}

unsigned int left_rot(unsigned int a, unsigned int b){
    b = b % 32;
    return (a << b) | (a >> (32-b));
}

unsigned int right_rot(unsigned int a, unsigned int b){
    b = b % 32;
    return (a >> b) | (a << (32-b));
}

void encryption(const unsigned char m[16], unsigned char ci[16], unsigned char s[16]){
    unsigned int l[44];
    generate_roundkey(s, l);
    unsigned int a, b, c, d;
    a = 0; b = 0; c = 0; d = 0;
    for(int i = 0; i < 4; i ++) {
        a += (((unsigned int) m[i]) << (unsigned int)(24-8*i));
        b += (((unsigned int) m[4+i]) << (unsigned int)(24-8*i));
        c += (((unsigned int) m[8+i]) << (unsigned int)(24-8*i));
        d += (((unsigned int) m[12+i]) << (unsigned int)(24-8*i));
    }
    unsigned int t, u, temp;
    b += l[0];
    d += l[1];
    for(int j = 0; j < 20; j ++){
        t = left_rot(b*(2*b+1), 5);
        u = left_rot(d*(2*d+1), 5);
        a = left_rot((a^t), u) + l[2 * j + 2];
        c = left_rot((c ^ u), t) + l[2 * j + 3];
        temp = a;
        a = b;
        b = c;
        c = d;
        d = temp;
    }
    a = a + l[42];
    c = c + l[43];
    unsigned int temp1;
    for(int k = 0; k < 4; k ++){
        temp1 = a & (255 << (24 - 8*k));
        ci[k] = (temp1 >> (24 - 8*k)) & 255;
        temp1 = b & (255 << (24 - 8*k));
        ci[k+4] = (temp1 >> (24 - 8*k)) & 255;
        temp1 = c & (255 << (24 - 8*k));
        ci[k+8] = (temp1 >> (24 - 8*k)) & 255;
        temp1 = d & (255 << (24 - 8*k));
        ci[k+12] = (temp1 >> (24 - 8*k)) & 255;
    }
}


void decryption(unsigned char m[16], const unsigned char ci[16], unsigned char s[16]){
    unsigned int l[44];
    generate_roundkey(s, l);
    unsigned int a, b, c, d;
    a = 0; b = 0; c = 0; d = 0;
    for(int i = 0; i < 4; i ++) {
        a += (((unsigned int) ci[i]) << (24-8*i));
        b += (((unsigned int) ci[4+i]) << (24-8*i));
        c += (((unsigned int) ci[8+i]) << (24-8*i));
        d += (((unsigned int) ci[12+i]) << (24-8*i));
    }
    unsigned int t, u, temp;
    c -= l[43];
    a -= l[42];
    for(int j = 20; j > 0; j --){
        temp = a;
        a = d;
        d = c;
        c = b;
        b = temp;
        u = left_rot(d*(2*d+1), 5);
        t = left_rot(b*(2*b+1), 5);
        temp = right_rot((c - l[2 * j + 1]), t);
        c = temp ^ u;
        temp = right_rot((a - l[2 * j]), u);
        a = temp ^ t;
    }
    d = d - l[1];
    b = b - l[0];
    unsigned int temp1;
    for(int k = 0; k < 4; k ++){
        temp1 = a & (255 << (24 - 8*k));
        m[k] = (temp1 >> (24 - 8*k)) & 255;
        temp1 = b & (255 << (24 - 8*k));
        m[k+4] = (temp1 >> (24 - 8*k)) & 255;
        temp1 = c & (255 << (24 - 8*k));
        m[k+8] = (temp1 >> (24 - 8*k)) & 255;
        temp1 = d & (255 << (24 - 8*k));
        m[k+12] = (temp1 >> (24 - 8*k)) & 255;
    }
}