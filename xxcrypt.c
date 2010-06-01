#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "xxcrypt.h"

int c_long2str(int* v,int lv,int w,char** buf) {
	int n;
	int m;
	int i;
    n = (lv-1) * 4;
	*buf = (char*)malloc(n+4);
    if(w) {
        m = v[lv - 1];
        if ((m < n - 3) || (m > n)) {
			return 0;
		}
        n = m;
    }else{
		n = lv * 4;
	}
    for(i = 0; i < lv; i++) {
		*(((int*)(*buf))+i) = v[i];
    }
	return n;
}
int c_str2long(char* s,int ls,int w,int** res) {
	int add;
	char* buf;
	int i;
	int lr;
	if(w){
		w = 1;
	}else{
		w = 0;
	}
	add = (4 - ls % 4) & 3;
	if(add){
		buf = (char*)malloc(ls+add);
		memcpy(buf,s,ls);
		memset(buf+ls,0,add);
	}else{
		buf = s;
	}
	lr = (ls+add)/4 + w;
	*res = (int*)malloc(lr*4);
	for(i=0;i<lr-w;i++){
		(*res)[i] = *(((int*)buf)+i);
	}
    if(w) {
        (*res)[lr-1] = ls;
    }
	if(add){
		free(buf);
	}
    return lr;
}
int c_xxtea_encrypt(char* str,int lstr,char* key,int lkey,char** res){
	int* v;
	int lv;
	int* k;
	int lk;
	int lres;
	int* tmp;
	int i;
	int n;
	int z;
	int y;
	int delta;
	int q;
	int sum;
	int e;
	int p;
	int mx;
    if (lstr == 0 ) {
        return 0;
    }
    lv = c_str2long(str,lstr, 1,&v);
    lk = c_str2long(key,lkey, 0,&k);
    if (lk < 4) {
		tmp = (int*)malloc(4*4);
        for (i = 0; i < lk; i++) {
            tmp[i] = k[i];
        }
        for (i = lk; i < 4; i++) {
            tmp[i] = 0;
        }
		free(k);
		k = tmp;
    }
    n = lv - 1;
    z = v[n];
    y = v[0];
    delta = 0x9E3779B9;
    q = 6 + 52 / (n + 1);
    sum = 0;
    while (0 < q--) {
        sum = sum + delta;
        e = (sum >> 2) & 3;
        for (p = 0; p < n; p++) {
            y = v[p + 1];
            mx = (
				((z >> 5 & 0x07ffffff) ^ y << 2)
				+ ((y >> 3 & 0x1fffffff) ^ z << 4)
				)
				^ ((sum ^ y) + ( k[(p & 3) ^ e]	^ z	)
				);
            z = v[p] = v[p] + mx;
        }
        y = v[0];
        mx = (
			((z >> 5 & 0x07ffffff) ^ y << 2)
			+ ((y >> 3 & 0x1fffffff) ^ z << 4)
			) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z));
        z = v[n] = (v[n] + mx);
    }
    lres = c_long2str(v,lv, 0,res);
	free(v);
	free(k);
	return lres;
}
int c_xxtea_decrypt(char* str,int lstr,char* key,int lkey,char** res){
	int* v;
	int lv;
	int* k;
	int lk;
	int lres;
	int* tmp;
	int i;
	int n;
	int z;
	int y;
	int delta;
	int q;
	int sum;
	int e;
	int p;
	int mx;
    if (lstr == 0 ) {
        return 0;
    }
    lv = c_str2long(str,lstr, 0,&v);
    lk = c_str2long(key,lkey, 0,&k);
    if (lk < 4) {
		tmp = (int*)malloc(4*4);
        for (i = 0; i < lk; i++) {
            tmp[i] = k[i];
        }
        for (i = lk; i < 4; i++) {
            tmp[i] = 0;
        }
		free(k);
		k = tmp;
    }

    n = lv - 1;

    z = v[n];
    y = v[0];
    delta = 0x9E3779B9;
    q = 6 + 52 / (n + 1);
    sum = q * delta;
    while (sum != 0) {
        e = sum >> 2 & 3;
        for (p = n; p > 0; p--) {
            z = v[p - 1];
            mx = (((z >> 5 & 0x07ffffff) ^ y << 2)
				+ ((y >> 3 & 0x1fffffff) ^ z << 4))
				^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z));
            y = v[p] = (v[p] - mx);
        }
        z = v[n];
        mx = (((z >> 5 & 0x07ffffff) ^ y << 2)
			+ ((y >> 3 & 0x1fffffff) ^ z << 4))
			^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z));
        y = v[0] = v[0] - mx;
        sum = sum - delta;
    }
    lres = c_long2str(v,lv,1,res);
	free(v);
	free(k);
	return lres;
}
