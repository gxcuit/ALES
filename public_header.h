#pragma once
#include <pbc.h>
#include "pbc_test.h"
#include <stdio.h>
#include <time.h>
#include <string.h>
#define  N  1000 //block number
#define  C  300//challlenge number
#define  TASK 100

element_t g, h, sk, pk, u;// agg_hash;;// , agg_data, agg_auth, 
pairing_t pairing;

typedef struct
{
	element_t data[N], authenticator[N];
	char *id;
}MyFile;

typedef struct
{
	int i[C];
	element_t vi[C];
}Challenge;

typedef struct
{
	element_t agg_data, agg_auth;
}Proof;

typedef struct
{
	element_t agg_data, agg_auth1, agg_auth2;
}LiuProof;