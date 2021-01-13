//
// Created by frank on 19-6-30.
//

#ifndef RS6_UTIL_H
#define RS6_UTIL_H

#include <iostream>
#include <cmath>
unsigned int left_rot(unsigned int a, unsigned int b);

unsigned int right_rot(unsigned int a, unsigned int b);

void generate_roundkey(const unsigned char s[16], unsigned int l[44]);

void encryption(const unsigned char m[16], unsigned char c[16], unsigned char s[16]);

void decryption(unsigned char m[16], const unsigned char c[16], unsigned char s[16]);

#endif //RS6_UTIL_H