#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/ecdh.h>
#include <openssl/fips.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>
#include <ctype.h>

//#include "fips_utl.h"


int main(int argc, char **argv)
{

	int curve_nids[5] = {0,0,0,0,0};

	printf("test");
	
	EC_GROUP_new_by_curve_name(curve_nids[1]);

	return 1;
}



