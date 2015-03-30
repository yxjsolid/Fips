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
char *dkmMsg = "Standard Test Message";

typedef struct _kasvsCfg
{
	int 			curve_nids;
	int 			hmacKeyBitSize;
	int 			hmacTagBitLen;
	const EVP_MD 	*hmacMD;
}kasvsCfg;


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
		{
			fprintf(rfp, "%02x", val[i]);
		}
		fputs(RESP_EOL, rfp);
	}

#if VERBOSE
    printf("%s = %.*s\n", tag, olen, obuf);
#endif
    }

void myPrintValue(char *tag, unsigned char *val, int len)
{

	//myOutputValue(tag, val, len, stdout, 0);

}

int kavasVerifyTag(const EVP_MD * md, char * key,long keyLen, char * macData, long macDataLen, char * tag, int tagLen)
{

	char *msg;
	int len;

	unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen;

#if 0
	printf("keylen = %d \n", keyLen);
	printf("ivLen = %d \n", macDataLen);
	
	myPrintValue("key", key, keyLen);
	myPrintValue("macData", macData, macDataLen);
#endif

	HMAC(md,key,keyLen,macData,macDataLen,out,&outlen);

	myPrintValue("md", out, tagLen);


	if (memcmp(out, tag, tagLen))
	{
		return 0;
	}

	return 1;
}



void kavasKDF(const EVP_MD * md, char * z, int zLen, char * oi, int oiLen, unsigned char * dkm, int keyLen)
{
	int hashLen = md->md_size;
 	char digest[SHA512_DIGEST_LENGTH];
	unsigned char *dkmPtr = dkm;
	char *buff = NULL;
	
	unsigned int cnt = 1;
	unsigned int cnt_bigendian = 0;
	int 		cntLen = 4;
	unsigned int reps =  keyLen/hashLen;

	
	do
	{
		buff = malloc(cntLen + zLen + oiLen);
		cnt_bigendian = htonl(cnt);
		memcpy(buff, (unsigned char*)&cnt_bigendian, cntLen);
		memcpy(buff + cntLen, z, zLen);
		memcpy(buff + cntLen + zLen, oi, oiLen);
		EVP_Digest(buff, cntLen + zLen + oiLen, digest,   NULL, md, NULL);

		memcpy(dkmPtr, digest, keyLen);
		dkmPtr += keyLen;
		free(buff);

	}while(cnt++ < reps);

}





#if 0
void testKdf()
{

	kdf(Z, OI, 112);
	


	
}
#endif
static int lookup_curve2(char *cname)
	{
	char *p;
	p = strchr(cname, ']');
	if (!p)
		{
		fprintf(stderr, "Parse error: missing ]\n");
		return NID_undef;
		}
	*p = 0;

	if (!strcmp(cname, "B-163"))
		return NID_sect163r2;
	if (!strcmp(cname, "B-233"))
		return NID_sect233r1;
	if (!strcmp(cname, "B-283"))
		return NID_sect283r1;
	if (!strcmp(cname, "B-409"))
		return NID_sect409r1;
	if (!strcmp(cname, "B-571"))
		return NID_sect571r1;
	if (!strcmp(cname, "K-163"))
		return NID_sect163k1;
	if (!strcmp(cname, "K-233"))
		return NID_sect233k1;
	if (!strcmp(cname, "K-283"))
		return NID_sect283k1;
	if (!strcmp(cname, "K-409"))
		return NID_sect409k1;
	if (!strcmp(cname, "K-571"))
		return NID_sect571k1;
	if (!strcmp(cname, "P-192"))
		return NID_X9_62_prime192v1;
	if (!strcmp(cname, "P-224"))
		return NID_secp224r1;
	if (!strcmp(cname, "P-256"))
		return NID_X9_62_prime256v1;
	if (!strcmp(cname, "P-384"))
		return NID_secp384r1;
	if (!strcmp(cname, "P-521"))
		return NID_secp521r1;

	fprintf(stderr, "Unknown Curve name %s\n", cname);
	return NID_undef;
	}

static int lookup_curve(char *cname)
	{
	char *p;
	p = strchr(cname, ':');
	if (!p)
		{
		fprintf(stderr, "Parse error: missing :\n");
		return NID_undef;
		}
	cname = p + 1;
	while(isspace(*cname))
		cname++;
	return lookup_curve2(cname);
	}

static const EVP_MD *eparse_kdf_md(char *line)
{
	char *p;
	if (line[0] != '[' || line[1] != 'E')
		return NULL;
	p = strchr(line, '-');
	if (!p)
		return NULL;
	line = p + 1;
	p = strchr(line, ']');
	if (!p)
		return NULL;
	*p = 0;
	p = line;
	while(isspace(*p))
		p++;
	if (!strcmp(p, "SHA1"))
		return EVP_sha1();
	else if (!strcmp(p, "SHA224"))
		return EVP_sha224();
	else if (!strcmp(p, "SHA256"))
		return EVP_sha256();
	else if (!strcmp(p, "SHA384"))
		return EVP_sha384();
	else if (!strcmp(p, "SHA512"))
		return EVP_sha512();
	else
		return NULL;
}

static const EVP_MD *eparse_hmac_md(char *line)
{
	char *p;
	p = strchr(line, ':');
	if (!p)
		return NULL;
	line = p + 1;
	p = strchr(line, ']');
	if (!p)
		return NULL;
	*p = 0;
	p = line;
	while(isspace(*p))
		p++;
	if (!strcmp(p, "SHA1"))
		return EVP_sha1();
	else if (!strcmp(p, "SHA224"))
		return EVP_sha224();
	else if (!strcmp(p, "SHA256"))
		return EVP_sha256();
	else if (!strcmp(p, "SHA384"))
		return EVP_sha384();
	else if (!strcmp(p, "SHA512"))
		return EVP_sha512();
	else
		return NULL;
}

static int eparse_size(char *line)
{
	char *p;
	int size = 0;
	p = strchr(line, ':');
	if (!p)
		return NULL;
	line = p + 1;
	p = strchr(line, ']');
	if (!p)
		return NULL;
	*p = 0;
	p = line;
	while(isspace(*p))
		p++;

	size = atoi(p); /* in bits */
	//printf("eparse_size = %d \n", size);

	return size;
}

int kavasHashZ(EC_GROUP *group, unsigned char *Z, int zLen, BIGNUM *cd, BIGNUM *cx, BIGNUM *cy, BIGNUM *id, BIGNUM *ix, BIGNUM *iy)
{
	EC_KEY *ec = NULL;
	EC_POINT *peerkey = NULL;
	int ret;


	ec = EC_KEY_new();
	EC_KEY_set_flags(ec, EC_FLAG_COFACTOR_ECDH);
	EC_KEY_set_group(ec, group);
	peerkey = make_peer(group, cx, cy);


#if 0

	if (!EC_KEY_set_public_key_affine_coordinates(ec, cx, cy))
	{
		//printf("key error \n");
		return 0;
	}
	

	if (!EC_KEY_set_public_key_affine_coordinates(ec, ix, iy))
	{
		//printf("key error \n");
		return 0;
	}
#endif
	
	EC_KEY_set_private_key(ec, id);
		

	ECDH_compute_key(Z, zLen, peerkey, ec, 0);
	myPrintValue("Z", Z, zLen);


}

int ECCOnePassDHUnifiedMain(int argc, char **argv)
{
	char **args = argv + 1;
	int argn = argc - 1;
	FILE *in, *out;
	char buf[2048], lbuf[2048];
	unsigned char *rhash = NULL;
	long rhashlen;
	BIGNUM *cd=NULL, *ecx = NULL, *ecy = NULL;
	BIGNUM *scx = NULL, *scy = NULL;
	BIGNUM *sid = NULL, *six = NULL, *siy = NULL;
	BIGNUM *eid = NULL, *eix = NULL, *eiy = NULL;;

	
	const EVP_MD *kdfMd = NULL;
	EC_GROUP *group = NULL;
	char *keyword = NULL, *value = NULL;
	int do_verify = -1, exout = 0;
	int rv = 1;


	int curve_nids[5];

	kasvsCfg curve_cfg[5];
	int param_set = -1;
	EC_KEY *ec = NULL;

	unsigned char *Z;
	unsigned char *Zs;
	unsigned char *Ze;
	unsigned char chash[EVP_MAX_MD_SIZE];
	int Zlen;
	int ret;

	unsigned char *oi = NULL;
	long oiLen = 0;

	unsigned char *nonce = NULL;
	int nonceLen = 0;

	unsigned char *dkm = NULL;


	unsigned char * macData = NULL;
	int 			macDataLen = 0;

	unsigned char *CAVSTag = NULL;
	int				tagLen = 0;


	int keySize = 0;

	int pass = 0;

	memset((unsigned char*)&(curve_cfg), 0, sizeof (curve_cfg));
	
	if (argn == 2)
		{
		in = fopen(*args, "r");
		if (!in)
			{
			fprintf(stderr, "Error opening input file\n");
			exit(1);
			}
		out = fopen(args[1], "w");
		if (!out)
			{
			fprintf(stderr, "Error opening output file\n");
			exit(1);
			}
		}
	else if (argn == 0)
		{
		in = stdin;
		out = stdout;
		}
	else
		{
		fprintf(stderr,"%s [dhver|dhgen|] [-exout] (infile outfile)\n",argv[0]);
		exit(1);
		}

	while (fgets(buf, sizeof(buf), in) != NULL)
	{
		fputs(buf, out);
		if (buf[0] == '[' && buf[1] == 'E')
		{
			int c = buf[2];
			if (c < 'A' || c > 'E')
				goto parse_error;
			param_set = c - 'A';
			/* If just [E?] then initial paramset */
			if (buf[3] == ']')
				continue;
			if (group)
				EC_GROUP_free(group);
			group = EC_GROUP_new_by_curve_name(curve_cfg[c - 'A'].curve_nids);
		}
		
		if (strlen(buf) > 10 && !strncmp(buf, "[Curve", 6))
		{
			int nid;
			if (param_set == -1)
				goto parse_error;
			nid = lookup_curve(buf);
			if (nid == NID_undef)
				goto parse_error;
			curve_cfg[param_set].curve_nids = nid;
		}

		if (strlen(buf) > 10 && !strncmp(buf, "[HMAC SHAs", 10))
		{
			kdfMd = eparse_hmac_md(buf);
			if (kdfMd == NULL)
				goto parse_error;

			curve_cfg[param_set].hmacMD = kdfMd;
			continue;
		}

		if (strlen(buf) > 10 && !strncmp(buf, "[HMACKeySize", 12))
		{
			int size = -1;
			size = eparse_size(buf);
			
			curve_cfg[param_set].hmacKeyBitSize = size;
			continue;
		}

		if (strlen(buf) > 10 && !strncmp(buf, "[HMAC Tag length", 16))
		{
			int size = -1;
			size = eparse_size(buf);
			
			curve_cfg[param_set].hmacTagBitLen = size;
			continue;
		}

		if (strlen(buf) > 4 && buf[0] == '[' && buf[2] == '-')
		{
			int nid = lookup_curve2(buf + 1);
			if (nid == NID_undef)
				goto parse_error;
			if (group)
				EC_GROUP_free(group);
			group = EC_GROUP_new_by_curve_name(nid);
			if (!group)
				{
				fprintf(stderr, "ERROR: unsupported curve %s\n", buf + 1);
				return 1;
				}
		}

		if (strlen(buf) > 6 && !strncmp(buf, "[E", 2))
		{
			kdfMd = eparse_kdf_md(buf);
			if (kdfMd == NULL)
				goto parse_error;
			continue;
		}

		
		if (!parse_line(&keyword, &value, lbuf, buf))
			continue;


//		printf("keyworkd = %s \n", keyword);
		if (!strcmp(keyword, "QeCAVSx"))
			{
			if (!do_hex2bn(&ecx, value))
				goto parse_error;
			}
		else if (!strcmp(keyword, "QeCAVSy"))
			{
			if (!do_hex2bn(&ecy, value))
				goto parse_error;

			}

		else if (!strcmp(keyword, "QsCAVSx"))
			{
			if (!do_hex2bn(&scx, value))
				goto parse_error;

			}

		else if (!strcmp(keyword, "QsCAVSy"))
			{
			if (!do_hex2bn(&scy, value))
				goto parse_error;

			}


		else if (!strcmp(keyword, "deCAVS"))
			{
			if (!do_hex2bn(&cd, value))
				goto parse_error;
			}
		
		else if (!strcmp(keyword, "deIUT"))
			{
			if (!do_hex2bn(&eid, value))
				goto parse_error;
			}
		else if (!strcmp(keyword, "dsIUT"))
			{
			if (!do_hex2bn(&sid, value))
				goto parse_error;
			}
		else if (!strcmp(keyword, "QsIUTx"))
			{
			if (!do_hex2bn(&six, value))
				goto parse_error;
			}
		else if (!strcmp(keyword, "QsIUTy"))
			{
			if (!do_hex2bn(&siy, value))
				goto parse_error;
			}

		else if (!strcmp(keyword, "QeIUTx"))
			{
			if (!do_hex2bn(&eix, value))
				goto parse_error;
			}
		else if (!strcmp(keyword, "QeIUTy"))
			{
			if (!do_hex2bn(&eiy, value))
				goto parse_error;
			}


		

		else if (!strcmp(keyword, "Nonce"))
		{
			nonce = hex2bin_m(value, &nonceLen);
			if (macData)
			{
				free(macData);
			}

			macDataLen = strlen(dkmMsg) + nonceLen;
			macData = malloc(macDataLen);
			memcpy(macData, dkmMsg, strlen(dkmMsg));
			memcpy(macData + strlen(dkmMsg), nonce, nonceLen);
			
		}		
		else if (!strcmp(keyword, "OI"))
			{
			if (!kdfMd)
				goto parse_error;
			oi = hex2bin_m(value, &oiLen);

		}
		else if (!strcmp(keyword, "CAVSTag"))
		{
			if (!kdfMd)
				goto parse_error;
			CAVSTag = hex2bin_m(value, &tagLen);


			Zlen = (EC_GROUP_get_degree(group) + 7)/8;

			Z = malloc(Zlen);

			Ze = Z;
			Zs = Z + Zlen;

			
			//printf("!!!!!!!!!  zlen = %d \n", Zlen);

			kavasHashZ(group, Z, Zlen, cd, ecx, ecy, sid, six, siy);

			//kavasHashZ(group, Ze, Zlen, cd, ecx, ecy, eid, ix, iy);
			//kavasHashZ(group, Zs, Zlen, cd, scx, scy, sid, ix, iy);

			myPrintValue("Z", Z, Zlen*2);
			
			keySize = curve_cfg[param_set].hmacKeyBitSize/8;



			dkm = malloc(keySize);
			memset(dkm, 0, keySize);
			kavasKDF(kdfMd, Z, Zlen, oi, oiLen, dkm, keySize);
			
			myPrintValue("dkm", dkm, keySize);
			pass = kavasVerifyTag(curve_cfg[param_set].hmacMD, dkm, keySize, macData, macDataLen, CAVSTag, tagLen);

			free(Z);
			free(dkm);
		}
		else if (!strcmp(keyword, "Result"))
		{
			if (pass)
			{
				if (value[0] != 'P')
				{
					printf("error!");
				}
			}
			else
			{
				if (value[0] != 'F')
				{
					printf("error!");
				}
			}
		}
		

	}
	rv = 0;
	parse_error:
	if (eid)
		BN_free(eid);
	if (six)
		BN_free(six);
	if (siy)
		BN_free(siy);
	if (scx)
		BN_free(scx);
	if (scy)
		BN_free(scy);
	if (group)
		EC_GROUP_free(group);
	if (in && in != stdin)
		fclose(in);
	if (out && out != stdout)
		fclose(out);
	if (rv)
		fprintf(stderr, "Error Parsing request file\n");
	return rv;
	}




int main(int argc, char **argv)
{
//	testHmac();


	//test1();

	ECCOnePassDHUnifiedMain(argc, argv);
}



