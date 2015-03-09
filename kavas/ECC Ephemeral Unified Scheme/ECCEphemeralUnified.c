#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/ecdh.h>
#include <openssl/fips.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>
#include <ctype.h>



#include "fips_utl.h"

static EC_POINT *make_peer(EC_GROUP *group, BIGNUM *x, BIGNUM *y)
	{
	EC_POINT *peer;
	int rv;
	BN_CTX *c;
	peer = EC_POINT_new(group);
	if (!peer)
		return NULL;
	c = BN_CTX_new();
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
		== NID_X9_62_prime_field)
		rv = EC_POINT_set_affine_coordinates_GFp(group, peer, x, y, c);
	else
#ifdef OPENSSL_NO_EC2M
		{
		fprintf(stderr, "ERROR: GF2m not supported\n");
		exit(1);
		}
#else
		rv = EC_POINT_set_affine_coordinates_GF2m(group, peer, x, y, c);
#endif

	BN_CTX_free(c);
	if (rv)
		return peer;
	EC_POINT_free(peer);
	return NULL;
	}




void myOutputValue(char *tag, unsigned char *val, int len, FILE *rfp,int bitmode)
    {
    char obuf[2048];
    int olen;

    if(bitmode)
	{
	olen=bin2bint(val,len,obuf);
    	fprintf(rfp, "%s = %.*s" RESP_EOL, tag, olen, obuf);
	}
    else
	{
	int i;
    	fprintf(rfp, "%s = ", tag);
	for (i = 0; i < len; i++)
		fprintf(rfp, "%02x", val[i]);
	fputs(RESP_EOL, rfp);
	}

#if VERBOSE
    printf("%s = %.*s\n", tag, olen, obuf);
#endif
    }

void myPrintValue(char *tag, unsigned char *val, int len)
{

	myOutputValue(tag, val, len, stdout, 0);

}

//[EB - SHA512]
//[Curve selected:  B-233]



#if 0
//COUNT = 18
char *deCAVS = "000000ffc7d15174cd268365ba064f70d0aa04d6c9e8f340a2ff0cd4b7fe1369";
char *QeCAVSx = "000003e246dcac5c843658c82452c9d17eed2eea5de92ee5939d9dc2acc2c51b";
char *QeCAVSy = "000001ab4977bd5e84089a8ff18fe929dc0cc56a4d3d128a31ea14836a72f811";
char *deIUT = "000000de7a63a0ac4e0d78525b748736c22268854e4b2b545ad61ae1b6629913";
char *QeIUTx = "0000015303855f7b030ae28a2d22582d8e37914f11f4dfc8d206abfe6966c9b7";
char *QeIUTy = "000001719074881420b6fb96369e72ae53a0f948a643094fdbb3da50bae2e041";
char *Z = "00c47e27e1d0004b3058168b70d833014649a7d669effd7ad079c2843207";
char *CAVSHashZZ = "24f3817fc122ba1b080107ac29076b89aa210a673c16f9616227a347b1d0813a226c3f401a2db23f9e92fe120ee68601c15446de9c637f7819c18d3c174b0b5e";
//Result = F (3 - CAVS's Ephemeral public key X fails PKV 5.6.2.5)

#endif

#if 0
//[EB - SHA224]


//COUNT = 0
char *deCAVS = "17eeeefbb3f3b2c901d7d083a88bbb1c3d152e4e234d48469ae7488c";
char *QeCAVSx = "606e1d22db02056ca548d9a8e8f5b14b810abff0a2dbe5bc5800de7e";
char *QeCAVSy = "b23caff3791f7a390d4ef49710adf2b1805dd52b793df80b31d89b80";
char *Nonce = "3c4967abb412bed7e4a0f1e309933212";
char *deIUT = "ff8d67a408fadc9e911d7284af0acae29a4e3fc7c2862d03829ef624";
char *QeIUTx = "a92c5cb077bbf429ae16352f7ddbb687927860b5fc5d5208d5e8a14e";
char *QeIUTy = "ee2e8616586ee3fbb7dc00fb5c85e64d27b17f2e9a862d73af9fbaf5";
char *OI = "a1b2c3d4e5434156536964f9c55e0b49ae535339c98384a2d9b02974606274a8c3818375a923e3c7a4a353ed13f3ca";
char *CAVSTag = "40a587c5c09c025a551453cfcdfb";
char *Z = "deac28b2b9c6d70397edca14d51a86e6cc65b3e1249f98e3db322e7b";
char *MacData = "5374616e646172642054657374204d6573736167653c4967abb412bed7e4a0f1e309933212";
char *DKM = "085bf63acea58c9b4d1abdd26572";
//Result = F (3 - CAVS's Ephemeral public key X fails PKV 5.6.2.5)


#endif

#if 0
//COUNT = 2
char *deCAVS = "bfa09bcfee9104c0dd260962d77f67d7014c9d2e6e070ca30eed53ac";
char *QeCAVSx = "e9fe70ab37c92e07952383a8e5e4e5ba29d5ee35c9305389a76eb12d";
char *QeCAVSy = "4a85aec257da3a0e264bd2546b2fe6041e335627e80ce2fe0a786f65";
char *Nonce = "63a040ca9fb8d1cbc11e749d568035f1";
char *deIUT = "7c6b7283b9e401ebca08811358aa8a891f34a26f6a04507f8ffacb4c";
char *QeIUTx = "6219aa51a67d675af7106ca5e9b5e283585a2eacd9074a02a1d91068";
char *QeIUTy = "19a7ebbdfa561fcf9028ab0e6fbfeba582102a4f71bb6822711fe27e";
char *OI = "a1b2c3d4e54341565369646138c266649b914df6545f3f4a151e35073dc61bfab7a6d5071ff7806627b7fa0c3ab5a4";
char *CAVSTag = "d52353ba2ffcb0dc3018dc1d234c";
char *Z = "0e8fb4d3c1826a02497a2fb82d31b3d87515b5d7b786fd97ba55d1b1";
char *MacData = "5374616e646172642054657374204d65737361676563a040ca9fb8d1cbc11e749d568035f1";
char *DKM = "bf7007e11c5918e27c1cac11c3b6";
//Result = P (13 - Z value should have leading 0 nibble )

#endif

#if 1
//[EB - SHA256]


//COUNT = 0
char *deCAVS = "0d174b65b97c87e1cddebc6b2312cbe5018cc41bad441e09bd034bce";
char *QeCAVSx = "d2d3b78e8c9426ea109d5900fe78e432766240b72e9d529e494ce699";
char *QeCAVSy = "e8e3f3eeab525456d4b23de625d503c29c57e966b9c9d91a8448f92c";
char *Nonce = "0bcde6707ec35b498c0e58fbbceeaa70";
char *deIUT = "c8a522ec5b021a38608f909fe8629032af99840a4264dfbdf533dba6";
char *QeIUTx = "0d24a83b2e985747ccd0d1c93b254dc00a30294bdd6235217069bf02";
char *QeIUTy = "0121f2811ca245eb5d9001c3ca42ee8d14e2c3199603ba2bcaa5c5d0";
char *OI = "a1b2c3d4e54341565369646dd91afbd96a2cbbfc1a0f74ee323cc9939853ef1c42bbc0d1f0890b0e1ba42f8c2826e8";
char *CAVSTag = "777485bf797319fb9268035cc497";
char *Z = "717aec8c7d2cbcc76e724cd1ce77e5d88aaa9664782978c8ab49f6e7";
char *MacData = "5374616e646172642054657374204d6573736167650bcde6707ec35b498c0e58fbbceeaa70";
char *DKM = "e6af0cfedd77ee94164e6c2258fd";
//Result = P (0 - Correct)

#endif


#if 1
//P-256
//sha-256
char *deU = "814264145F2F56F2E96A8E337A1284993FAF432A5ABCE59E867B7291D507A3AF";
char *QeU_x = "2AF502F3BE8952F2C9B5A8D4160D09E97165BE50BC42AE4A5E8D3B4BA83AEB15";
char *QeU_y = "EB0FAF4CA986C4D38681A0F9872D79D56795BD4BFF6E6DE3C0F5015ECE5EFD85";
char *deV = "2CE1788EC197E096DB95A200CC0AB26A19CE6BCCAD562B8EEE1B593761CF7F41";
char *QeV_x = "B120DE4AA36492795346E8DE6C2C8646AE06AAEA279FA775B3AB0715F6CE51B0";
char *QeV_y = "9F1B7EECE20D7B5ED8EC685FA3F071D83727027092A8411385C34DDE5708B2B6";
char *Zx = "DD0F5396219D1EA393310412D19A08F1F5811E9DC8EC8EEA7F80D21C820C2788";
char *OtherInfo = "123456789ABCDEF0414C494345313233424F424259343536";
char *DerivedKeyMaterial = "4C664A9BCA73D9819538F659B4B675C72FB95AC2F86527D98254F85E1041CBFA386EEA63B4DA8803B31383B544D33A0BC781F7C2F66A8CF41DE148E2D3328173";
char *KeyData = "4C664A9BCA73D9819538F659B4B675C72FB95AC2F86527D98254F85E1041CBFA386EEA63B4DA8803B31383B544D33A0BC781F7C2F66A8CF41DE148E2D3328173";

#endif



void kdf(char * z, char * ol, int keyLen)
{
	//int hashLen = SHA512_CBLOCK;
	int hashLen = SHA256_DIGEST_LENGTH *8;
	unsigned int i = 0;
	int resp = 0;
	char *cnt = "00000001";
 	char md[SHA256_DIGEST_LENGTH];
#if 0	
	EVP_MD *evp_md,
	


	unsigned char out[EVP_MAX_MD_SIZE];
	HMAC_CTX c;
	static unsigned char m[EVP_MAX_MD_SIZE];

	
	evp_md  = EVP_sha256();
	HMAC_CTX_init(&c);
	if (!HMAC_Init(&c,key,key_len,evp_md))
		goto err;
	if (!HMAC_Update(&c,out,n))
		goto err;
	if (!HMAC_Final(&c,md,md_len))
		goto err;
	HMAC_CTX_cleanup(&c);
	return md;
#endif

	SHA256_CTX c;



	SHA256_Init(&c);
	SHA256_Update(&c,cnt,8);
	SHA256_Update(&c,z,64);
	SHA256_Update(&c,ol,48);


	SHA256_Final(md,&c);


	myPrintValue("cnt", cnt, 8);
	myPrintValue("ol", ol, 24);
	myPrintValue("z", z, 32);
	myPrintValue("ol", ol, 24);


	myPrintValue("md", md, SHA256_DIGEST_LENGTH);



	
	resp = keyLen/hashLen;

	printf("hashLen = %d \n", hashLen);
	printf("keyLen = %d \n", keyLen);

	printf("resp = %d \n", resp);

	


	

}


int main(int argc, char **argv)
{

	int curve_nids[5] = {0,0,0,0,0};

	BIGNUM *cx = NULL, *cy = NULL;
	BIGNUM *id = NULL, *ix = NULL, *iy = NULL;


	const EVP_MD *md = NULL;

	EC_KEY *ec = NULL;
	EC_POINT *peerkey = NULL;
	unsigned char *Z;
	unsigned char chash[EVP_MAX_MD_SIZE];
	int Zlen;
	EC_GROUP *group = NULL;
	int ret = 0;

	deCAVS = deU;
	QeCAVSx = QeU_x;
	QeCAVSy = QeU_y;
	deIUT = deV;
	QeIUTx = QeV_x;
	QeIUTy = QeV_y;
	OI = OtherInfo;
	Z= Zx;

	md = EVP_sha256();

	do_hex2bn(&ix, QeIUTx);
	do_hex2bn(&iy, QeIUTy);

	do_hex2bn(&id, deIUT);
	do_hex2bn(&cx, QeCAVSx);
	do_hex2bn(&cy, QeCAVSy);


	group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);


	ec = EC_KEY_new();
	EC_KEY_set_flags(ec, EC_FLAG_COFACTOR_ECDH);
	EC_KEY_set_group(ec, group);
	peerkey = make_peer(group, cx, cy);

	ret = EC_KEY_set_public_key_affine_coordinates(ec, cx, cy);
	printf("\n\nret = %d\n", ret);
		
	ret = EC_KEY_set_public_key_affine_coordinates(ec, ix, iy);

	printf("\n\nret = %d\n", ret);
	EC_KEY_set_private_key(ec, id);
		
	Zlen = (EC_GROUP_get_degree(group) + 7)/8;
	Z = OPENSSL_malloc(Zlen);
	ECDH_compute_key(Z, Zlen, peerkey, ec, 0);

	myPrintValue("Z", Z, Zlen);

	FIPS_digest(Z, Zlen, chash, NULL, md);

	myPrintValue("chash", chash, EVP_MAX_MD_SIZE);


	kdf(Z, OI, 512);
	
	return 1;
}



