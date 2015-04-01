#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/ecdh.h>
//#include <openssl/fips.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>
#include <ctype.h>
#include "ecc_utl.h"

#define RESP_EOL	"\n"
char *dkmMsg = "Standard Test Message";

typedef enum
{
	ECC_TYPE_UNKNOWN,
	ECCFullUnified,
	ECCEphemeralUnified,
	ECCOnePassUnified,
	ECCOnePassDH,
	ECCStaticUnified
} ECC_VALIDATE_TYPE;



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
	


	unsigned char tagOut[EVP_MAX_MD_SIZE];
    unsigned int tagOutLen;

	HMAC(md,key,keyLen,macData,macDataLen,tagOut,&tagOutLen);
	myPrintValue("md", tagOut, tagLen);
	if (memcmp(tagOut, tag, tagLen))
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
		return -1;
	line = p + 1;
	p = strchr(line, ']');
	if (!p)
		return -1;
	*p = 0;
	p = line;
	while(isspace(*p))
		p++;

	size = atoi(p); /* in bits */
	return size;
}

int kavasHashZ(EC_GROUP *group, unsigned char *Z, int zLen, BIGNUM *x, BIGNUM *y, BIGNUM *d)
{
	EC_KEY *ec = NULL;
	EC_POINT *peerkey = NULL;
	int ret;

	ec = EC_KEY_new();
//	EC_KEY_set_flags(ec, EC_FLAG_COFACTOR_ECDH);
	EC_KEY_set_group(ec, group);
	peerkey = make_peer(group, x, y);


	EC_KEY_set_private_key(ec, d);
	ECDH_compute_key(Z, zLen, peerkey, ec, 0);
	myPrintValue("Z", Z, zLen);
}

ECC_VALIDATE_TYPE getEccValidateType(int uStatic, int uEphemeral, int vStatic, int vEphemeral)
{
	ECC_VALIDATE_TYPE type = ECC_TYPE_UNKNOWN;
	if (uStatic && vStatic)
	{
		if (uEphemeral && vEphemeral)
		{
			type =  ECCFullUnified;
		}
		else if(uEphemeral || vEphemeral)
		{
			type = ECCOnePassUnified;
		}
	}
	else if(uStatic || vStatic)
	{
		type =  ECCOnePassDH;
	}
	else
	{
		type =  ECCEphemeralUnified;
	}
	
	return type;
}


int parseEccTestType(char * buff, int *isValidateTest, ECC_VALIDATE_TYPE *eccType, int *isInitiator)
{
	ECC_VALIDATE_TYPE type = ECC_TYPE_UNKNOWN;

	*eccType = type;
	*isInitiator = 0;

	if (strstr(buff, "Function"))
	{
		*isValidateTest =  0;
	}
	else if (strstr(buff, "Validity"))
	{
		*isValidateTest =  1;
	}
	
	if (strstr(buff, "dhEphemeralUnified"))
	{
		type =  ECCEphemeralUnified;
	}
	else if (strstr(buff, "dhFullUnified"))
	{
		type =  ECCFullUnified;
	}
	else if (strstr(buff, "dhOnePassDH"))
	{
		type =  ECCOnePassDH;
	}
	else if (strstr(buff, "dhOnePassUnified"))
	{
		type =  ECCOnePassUnified;
	}
	else if (strstr(buff, "dhStaticUnified"))
	{
		type =  ECCStaticUnified;
	}
	else
	{
		return 0;
	}
		

	if(strstr(buff, "Initiator"))
	{
		*isInitiator = 1;
	}

	*eccType = type;

	return 1;
}

int parseEccTestParam(char * buf, kasvsCfg *curveCfgPtr, int *isValidateTest, ECC_VALIDATE_TYPE *eccType, int *isInitiator)
{
	static int param_set;
	const EVP_MD *hmacMd = NULL;
	
	if(buf[0] == '#' && strstr(buf, "ECC"))
	{
		if (!parseEccTestType(buf, isValidateTest, eccType, isInitiator))
		{
			printf("parseEccTestType error \n");
			return -1;
		}

		printf("eccType = %d \n", *eccType);
		printf("isInitiator = %d \n", *isInitiator);
	}


	if (buf[0] == '[' && buf[1] == 'E')
	{
		int c = buf[2];
		param_set = -1;
		if (c < 'A' || c > 'E')
		{
			printf("error!! %s %d \n", __FUNCTION__, __LINE__);
			return -1;
		}
		param_set = c - 'A';
		/* If just [E?] then initial paramset */
		if (buf[3] == ']')
			return 1;
	}
	
	if (strlen(buf) > 10 && !strncmp(buf, "[Curve", 6))
	{
		int nid;
		if (param_set == -1)
		{
			printf("error!! %s %d \n", __FUNCTION__, __LINE__);
			return -1;
		}
		nid = lookup_curve(buf);
		if (nid == NID_undef)
		{
			printf("error!! %s %d \n", __FUNCTION__, __LINE__);
			return -1;
		}
		(curveCfgPtr + param_set)->curve_nids = nid;
		printf("nid = %d \n", nid);
	}

	if (strlen(buf) > 10 && !strncmp(buf, "[HMAC SHAs", 10))
	{
		hmacMd = eparse_hmac_md(buf);
		if (hmacMd == NULL)
		{
			printf("error!! %s %d \n", __FUNCTION__, __LINE__);
			return -1;
		}
		(curveCfgPtr + param_set)->hmacMD = hmacMd;
		return 1;
	}

	if (strlen(buf) > 10 && !strncmp(buf, "[HMACKeySize", 12))
	{
		int size = -1;
		size = eparse_size(buf);
		
		(curveCfgPtr + param_set)->hmacKeyBitSize = size;
		return 1;
	}

	if (strlen(buf) > 10 && !strncmp(buf, "[HMAC Tag length", 16))
	{
		int size = -1;
		size = eparse_size(buf);
		
		(curveCfgPtr + param_set)->hmacTagBitLen = size;
		return 1;
	}


	return 0;
}



int main(int argc, char **argv)
{
	char **args = argv + 1;
	int argn = argc - 1;
	FILE *in, *out;
	char buf[2048], lbuf[2048];
	char *keyword = NULL, *value = NULL;

	BIGNUM *deu = NULL, *qeux = NULL, *qeuy = NULL;
	BIGNUM *dsu = NULL, *qsux = NULL, *qsuy = NULL;
	BIGNUM *dev = NULL, *qevx = NULL, *qevy = NULL;
	BIGNUM *dsv = NULL, *qsvx = NULL, *qsvy = NULL;

	EC_GROUP *group = NULL;
	const EVP_MD *kdfMd = NULL;
	
	
	int rv = 1;

	kasvsCfg curve_cfg[5];
	int param_set = -1;
	

	unsigned char *Z;
	int 			Zlen;

	
	unsigned char *Zs;
	unsigned char *Ze;
	
	unsigned char 	*oi = NULL;
	long 			oiLen = 0;

	unsigned char 	*nonce = NULL;
	long 			nonceLen = 0;

	unsigned char *dkm = NULL;


	unsigned char * macData = NULL;
	int 			macDataLen = 0;

	unsigned char 	*CAVSTag = NULL;
	long				tagLen = 0;


	int 	keySize = 0;

	int 	pass = 0;

	int 	cnt = 0;
	char  bufTmp[128];

	int uStatic = 0, uEphemeral = 0;
	int vStatic = 0, vEphemeral = 0;
	ECC_VALIDATE_TYPE eccType = 0;
	
	unsigned char tagOut[EVP_MAX_MD_SIZE];
    unsigned int tagOutLen;
	int showError = -1;
	int ret = 0;
	int isInitiator = 1;
	int isValidateTest = 0;
	

	memset((unsigned char*)&(curve_cfg), 0, sizeof (curve_cfg));


	if (argn && !strcmp(*args, "showError"))
		{
		showError = 1;
		args++;
		argn--;
		}
	else if (argn && !strcmp(*args, "quiet"))
		{
		showError = 0;
		args++;
		argn--;
		}


	if (showError == -1)
	{
		fprintf(stderr,"%s [showError|quiet|] [-exout] (infile outfile)\n",argv[0]);
		exit(1);
	}
	
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

		ret = parseEccTestParam(buf, (kasvsCfg *)&curve_cfg, &isValidateTest, &eccType, &isInitiator);

		if (ret == -1)
		{
			goto parse_error;
		}
		else if (ret == 1)
		{
			continue;
		}

	//	printf("%s \n", buf);
		//
		//printf("%s %d \n", __FUNCTION__, __LINE__);




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
		

		if (strlen(buf) > 6 && !strncmp(buf, "[E", 2))
		{
			memset(bufTmp, 0, 128);
			memcpy(bufTmp, buf, strlen(buf));
		
			kdfMd = eparse_kdf_md(buf);
			if (kdfMd == NULL)
				goto parse_error;
			continue;
		}

		if (!parse_line(&keyword, &value, lbuf, buf))
			continue;

		if (!strcmp(keyword, "QeCAVSx"))
		{
			if (!do_hex2bn(&qevx, value))
				goto parse_error;
		}

		else if (!strcmp(keyword, "COUNT"))
		{
			cnt = atoi(value); /* in bits */
		}
		else if (!strcmp(keyword, "QeCAVSy"))
		{
			if (!do_hex2bn(&qevy, value))
				goto parse_error;

			vEphemeral = 1;
		}
		else if (!strcmp(keyword, "QsCAVSx"))
		{
			if (!do_hex2bn(&qsvx, value))
				goto parse_error;
		}
		else if (!strcmp(keyword, "QsCAVSy"))
		{
			if (!do_hex2bn(&qsvy, value))
				goto parse_error;

			vStatic = 1;
		}
		else if (!strcmp(keyword, "dsCAVS"))
		{
			if (!do_hex2bn(&dsv, value))
				goto parse_error;
		}
		else if (!strcmp(keyword, "deCAVS"))
		{
			if (!do_hex2bn(&dev, value))
				goto parse_error;
		}
		else if (!strcmp(keyword, "deIUT"))
		{
			if (!do_hex2bn(&deu, value))
				goto parse_error;
		}
		else if (!strcmp(keyword, "dsIUT"))
		{
			if (!do_hex2bn(&dsu, value))
				goto parse_error;
		}
		else if (!strcmp(keyword, "QsIUTx"))
		{
			if (!do_hex2bn(&qsux, value))
				goto parse_error;
		}
		else if (!strcmp(keyword, "QsIUTy"))
		{
			if (!do_hex2bn(&qsuy, value))
				goto parse_error;

			uStatic= 1;
		}
		else if (!strcmp(keyword, "QeIUTx"))
		{
			if (!do_hex2bn(&qeux, value))
				goto parse_error;
		}
		else if (!strcmp(keyword, "QeIUTy"))
		{
			if (!do_hex2bn(&qeuy, value))
				goto parse_error;
			uEphemeral = 1;
		}
		else if (!strcmp(keyword, "Nonce"))
		{

			if (macData)
			{
				free(macData);
			}

			if (nonce)
			{
				OPENSSL_free(nonce);
			}

		
			nonce = hex2bin_m((const char *)value, &nonceLen);
			macDataLen = strlen(dkmMsg) + nonceLen;
			macData = malloc(macDataLen);
			memcpy(macData, dkmMsg, strlen(dkmMsg));
			memcpy(macData + strlen(dkmMsg), nonce, nonceLen);
		}		
		else if (!strcmp(keyword, "OI"))
		{
			if (!kdfMd)
				goto parse_error;

			if (oi)
			{
				OPENSSL_free(oi);
			}
			
			oi = hex2bin_m((const char *)value, &oiLen);

		}
		else if (!strcmp(keyword, "CAVSTag"))
		{
			if (!kdfMd)
				goto parse_error;

			if (CAVSTag)
			{
				OPENSSL_free(CAVSTag);
			}

			
			
			CAVSTag = hex2bin_m(value, &tagLen);
			Zlen = (EC_GROUP_get_degree(group) + 7)/8;
			switch (eccType)
			{
				case ECCFullUnified:
				{
					Z = malloc(Zlen*2);
					Ze = Z;
					Zs = Z + Zlen;
					kavasHashZ(group, Ze, Zlen, qevx, qevy, deu);
					kavasHashZ(group, Zs, Zlen, qsvx, qsvy, dsu);

					Zlen*= 2;

					break;
				}
					
				case ECCEphemeralUnified:
				{
					Z = malloc(Zlen);
					kavasHashZ(group, Z, Zlen, qevx, qevy, deu);
					break;
				}

				case ECCOnePassUnified:
				{
					Z = malloc(Zlen*2);
					Ze = Z;
					Zs = Z + Zlen;
					if (isInitiator)
					{
						kavasHashZ(group, Ze, Zlen, qsvx, qsvy, deu);
						kavasHashZ(group, Zs, Zlen, qsvx, qsvy, dsu);
					}
					else
					{
						kavasHashZ(group, Ze, Zlen, qevx, qevy, dsu);
						kavasHashZ(group, Zs, Zlen, qsvx, qsvy, dsu);
					}

					Zlen*= 2;

					break;
				}

				case ECCOnePassDH:
				{
					Z = malloc(Zlen);
					if (isInitiator)
					{
						kavasHashZ(group, Z, Zlen, qsvx, qsvy, deu);
					}
					else
					{
						kavasHashZ(group, Z, Zlen, qevx, qevy, dsu);
					}
					
					break;
				}

				case ECCStaticUnified:
				{
					break;
				}

				default:
					printf("not found validate type!!!\n");
					break;

			}


			pass = 0;

			keySize = curve_cfg[param_set].hmacKeyBitSize/8;
			dkm = malloc(keySize);
			memset(dkm, 0, keySize);
			kavasKDF(kdfMd, Z, Zlen, oi, oiLen, dkm, keySize);
			myPrintValue("dkm", dkm, keySize);
			
			HMAC(curve_cfg[param_set].hmacMD, dkm, keySize, macData, macDataLen, tagOut, &tagOutLen);
			myPrintValue("md", tagOut, tagLen);
			OutputValue("IUTTag", tagOut, tagLen, out, 0);
			if (memcmp(tagOut, CAVSTag, tagLen))
			{
				pass = 0;
				fputs("Result = F\n", out);
				if (showError)
					printf("error !!! \n");
				
			}
			else
			{
				pass = 1;
				fputs("Result = P\n", out);
			}
			
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
					printf("bufTmp = %s cnt[%d], error!\n",bufTmp, cnt);
				}
			}
		}
		

	}
	rv = 0;
	parse_error:

#if 1
	if (deu)
		BN_free(deu);
	if (qeux)
		BN_free(qeux);
	if (qeuy)
		BN_free(qeuy);
	if (dsu)
		BN_free(dsu);
	if (qsux)
		BN_free(qsux);
	if (qsuy)
		BN_free(qsuy);

	if (dev)
		BN_free(dev);
	if (qevx)
		BN_free(qevx);
	if (qevy)
		BN_free(qevy);
	if (dsv)
		BN_free(dsv);
	if (qsvx)
		BN_free(qsvx);
	if (qsvy)
		BN_free(qsvy);
	
	if (group)
		EC_GROUP_free(group);
	if (in && in != stdin)
		fclose(in);
	if (out && out != stdout)
		fclose(out);
#endif	
	if (rv)
		fprintf(stderr, "Error Parsing request file\n");
	return rv;	
}



