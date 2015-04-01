#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/ecdh.h>
#include <openssl/fips.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <string.h>
#include <ctype.h>
//#include "fips_utl.h"
char *dkmMsg = "Standard Test Message";
#define RESP_EOL	"\r\n"
#define CAVSid "CAVSid"
#define IUTid "IUTid"
#define ECC_OTHER_INFO "abcdefghijklmnopqrstuvwxyz0123456789"

typedef struct ec_extra_data_st {
	struct ec_extra_data_st *next;
	void *data;
	void *(*dup_func)(void *);
	void (*free_func)(void *);
	void (*clear_free_func)(void *);
} EC_EXTRA_DATA; /* used in EC_GROUP */

struct ec_key_st {
	int version;

	EC_GROUP *group;

	EC_POINT *pub_key;
	BIGNUM	 *priv_key;

	unsigned int enc_flag;
	point_conversion_form_t conv_form;

	int 	references;
	int	flags;

	EC_EXTRA_DATA *method_data;
} /* EC_KEY */;

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
int bin2bint(const unsigned char *in,int len,char *out)
    {
    int n;

    for(n=0 ; n < len ; ++n)
	out[n]=(in[n/8]&(0x80 >> (n%8))) ? '1' : '0';
    return n;
    }

int hex2bin(const char *in, unsigned char *out)
    {
    int n1, n2, isodd = 0;
    unsigned char ch;

    n1 = strlen(in);
    if (in[n1 - 1] == '\n')
	n1--;

    if (n1 & 1)
	isodd = 1;

    for (n1=0,n2=0 ; in[n1] && in[n1] != '\n' ; )
	{ /* first byte */
	if ((in[n1] >= '0') && (in[n1] <= '9'))
	    ch = in[n1++] - '0';
	else if ((in[n1] >= 'A') && (in[n1] <= 'F'))
	    ch = in[n1++] - 'A' + 10;
	else if ((in[n1] >= 'a') && (in[n1] <= 'f'))
	    ch = in[n1++] - 'a' + 10;
	else
	    return -1;
	if(!in[n1])
	    {
	    out[n2++]=ch;
	    break;
	    }
	/* If input is odd length first digit is least significant: assumes
	 * all digits valid hex and null terminated which is true for the
	 * strings we pass.
	 */
	if (n1 == 1 && isodd)
		{
		out[n2++] = ch;
		continue;
		}
	out[n2] = ch << 4;
	/* second byte */
	if ((in[n1] >= '0') && (in[n1] <= '9'))
	    ch = in[n1++] - '0';
	else if ((in[n1] >= 'A') && (in[n1] <= 'F'))
	    ch = in[n1++] - 'A' + 10;
	else if ((in[n1] >= 'a') && (in[n1] <= 'f'))
	    ch = in[n1++] - 'a' + 10;
	else
	    return -1;
	out[n2++] |= ch;
	}
    return n2;
    }

unsigned char *hex2bin_m(const char *in, long *plen)
	{
	unsigned char *p;
	if (strlen(in) == 0)
		{
		*plen = 0;
		return OPENSSL_malloc(1);
		}
	p = OPENSSL_malloc((strlen(in) + 1)/2);
	*plen = hex2bin(in, p);
	return p;
	}

int do_hex2bn(BIGNUM **pr, const char *in)
	{
	unsigned char *p;
	long plen;
	int r = 0;
	p = hex2bin_m(in, &plen);
	if (!p)
		return 0;
	if (!*pr)
		*pr = BN_new();
	if (!*pr)
		return 0;
	if (BN_bin2bn(p, plen, *pr))
		r = 1;
	OPENSSL_free(p);
	return r;
	}

int do_bn_print(FILE *out, const BIGNUM *bn)
	{
	int len, i;
	unsigned char *tmp;
	len = BN_num_bytes(bn);
	if (len == 0)
		{
		fputs("00", out);
		return 1;
		}

	tmp = OPENSSL_malloc(len);
	if (!tmp)
		{
		fprintf(stderr, "Memory allocation error\n");
		return 0;
		}
	BN_bn2bin(bn, tmp);
	for (i = 0; i < len; i++)
		fprintf(out, "%02x", tmp[i]);
	OPENSSL_free(tmp);
	return 1;
	}

int do_bn_print_name(FILE *out, const char *name, const BIGNUM *bn)
	{
	int r;
	fprintf(out, "%s = ", name);
	r = do_bn_print(out, bn);
	if (!r)
		return 0;
	fputs(RESP_EOL, out);
	return 1;
	}

void OutputValue(char *tag, unsigned char *val, int len, FILE *rfp,int bitmode)
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


int parse_line(char **pkw, char **pval, char *linebuf, char *olinebuf)
	{
	return parse_line2(pkw, pval, linebuf, olinebuf, 1);
	}

int parse_line2(char **pkw, char **pval, char *linebuf, char *olinebuf, int eol)
	{
	char *keyword, *value, *p, *q;
	strcpy(linebuf, olinebuf);
	keyword = linebuf;
	/* Skip leading space */
	while (isspace((unsigned char)*keyword))
		keyword++;

	/* Look for = sign */
	p = strchr(linebuf, '=');

	/* If no '=' exit */
	if (!p)
		return 0;

	q = p - 1;

	/* Remove trailing space */
	while (isspace((unsigned char)*q))
		*q-- = 0;

	*p = 0;
	value = p + 1;

	/* Remove leading space from value */
	while (isspace((unsigned char)*value))
		value++;

	/* Remove trailing space from value */
	p = value + strlen(value) - 1;

	if (eol && *p != '\n')
		fprintf(stderr, "Warning: missing EOL\n");

	while (*p == '\n' || isspace((unsigned char)*p))
		*p-- = 0;

	*pkw = keyword;
	*pval = value;
	return 1;
	}

BIGNUM *hex2bn(const char *in)
    {
    BIGNUM *p=NULL;

    if (!do_hex2bn(&p, in))
	return NULL;

    return p;
    }

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

int parseEccTestType(char * buff, ECC_VALIDATE_TYPE *eccType, int *isInitiator)
{
	ECC_VALIDATE_TYPE type = ECC_TYPE_UNKNOWN;

	*eccType = type;
	*isInitiator = 0;
	
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


#if 1
int My_EC_KEY_generate_key(EC_KEY *eckey)
	{	
	int	ok = 0;
	BN_CTX	*ctx = NULL;
	BIGNUM	*priv_key = NULL, *order = NULL;
	EC_POINT *pub_key = NULL;



	if (!eckey || !eckey->group)
		{
		ECerr(EC_F_EC_KEY_GENERATE_KEY, ERR_R_PASSED_NULL_PARAMETER);
		printf("error 1111 \n");
		return 0;
		}

	if ((order = BN_new()) == NULL) goto err;
	if ((ctx = BN_CTX_new()) == NULL) goto err;

	if (eckey->priv_key == NULL)
		{
		priv_key = BN_new();
		if (priv_key == NULL)
		{
			printf("error 2222 \n");
			goto err;
		}
		}
	else
		priv_key = eckey->priv_key;

	if (!EC_GROUP_get_order(eckey->group, order, ctx))
	{
		printf("error 333 \n");
		goto err;
	}



	do
		if (!BN_rand_range(priv_key, order))
			goto err;
	while (BN_is_zero(priv_key));

	if (eckey->pub_key == NULL)
		{
		pub_key = EC_POINT_new(eckey->group);
		if (pub_key == NULL)
			goto err;
		}
	else
		pub_key = eckey->pub_key;

	if (!EC_POINT_mul(eckey->group, pub_key, priv_key, NULL, NULL, ctx))
		goto err;

	eckey->priv_key = priv_key;
	eckey->pub_key  = pub_key;



	ok=1;


	//do_bn_print_name(stdout, "priv_key", priv_key);

err:	
	if (order)
		BN_free(order);
	if (pub_key  != NULL && eckey->pub_key  == NULL)
		EC_POINT_free(pub_key);
	if (priv_key != NULL && eckey->priv_key == NULL)
		BN_free(priv_key);
	if (ctx != NULL)
		BN_CTX_free(ctx);
	return(ok);
	}
#endif

static int my_ec_print_key(FILE *out, EC_KEY *key, int add_e, int exout)
{
	const EC_POINT *pt;
	const EC_GROUP *grp;
	const EC_METHOD *meth;
	int rv;
	BIGNUM *tx, *ty;
	const BIGNUM *d = NULL;
	BN_CTX *ctx;
	ctx = BN_CTX_new();
	if (!ctx)
		return 0;
	tx = BN_CTX_get(ctx);
	ty = BN_CTX_get(ctx);
	if (!tx || !ty)
		return 0;

	

	grp = EC_KEY_get0_group(key);



	pt = EC_KEY_get0_public_key(key);



	if (exout)
		d = EC_KEY_get0_private_key(key);


	meth = EC_GROUP_method_of(grp);
	if (EC_METHOD_get_field_type(meth) == NID_X9_62_prime_field)
	{	

		rv = EC_POINT_get_affine_coordinates_GFp(grp, pt, tx, ty, ctx);

	}
	else
	{

		rv = EC_POINT_get_affine_coordinates_GF2m(grp, pt, tx, ty, ctx);

	}


	if (add_e)
	{
		if (d)
			do_bn_print_name(out, "deIUT", d);
		do_bn_print_name(out, "QeIUTx", tx);
		do_bn_print_name(out, "QeIUTy", ty);
		
	}
	else
	{
		if (d)
			do_bn_print_name(out, "dsIUT", d);
		do_bn_print_name(out, "QsUTx", tx);
		do_bn_print_name(out, "QsUTy", ty);
		
	}



	BN_CTX_free(ctx);

	return rv;
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
	int isInitiator = 1;

	int genValidate = -1;

	EC_KEY *ke = NULL;
	EC_KEY *ks = NULL;			

	
	//fips_algtest_init();
	memset((unsigned char*)&(curve_cfg), 0, sizeof (curve_cfg));


	if (argn && !strcmp(*args, "genValidate"))
		{
		genValidate = 1;
		args++;
		argn--;
		}
	else if (argn && !strcmp(*args, "genResp"))
		{
		genValidate = 0;
		args++;
		argn--;
		}


	if (genValidate == -1)
	{
		fprintf(stderr,"%s [genValidate|genResp|] [-exout] (infile outfile)\n",argv[0]);
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

		if(buf[0] == '#' && strstr(buf, "ECC Function Test"))
		{
			if (!parseEccTestType(buf,&eccType, &isInitiator))
			{
				printf("parseEccTestType error \n");
				goto parse_error;
			}

			printf("eccType = %d \n", eccType);
			printf("isInitiator = %d \n", isInitiator);
		}


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
			printf("nid = %d \n", nid);
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
			int ret = 0;

			

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





			oiLen = strlen(IUTid) + strlen(CAVSid) + strlen(ECC_OTHER_INFO);
			oi = malloc(oiLen);


			
			if (isInitiator)
			{
				memcpy(oi, IUTid, strlen(IUTid));
				memcpy(oi + strlen(IUTid), CAVSid, strlen(CAVSid));
			}
			else
			{
				memcpy(oi, CAVSid, strlen(CAVSid));
				memcpy(oi + strlen(CAVSid), IUTid, strlen(IUTid));
			}
			memcpy(oi + strlen(IUTid) + strlen(CAVSid), ECC_OTHER_INFO, strlen(ECC_OTHER_INFO));
			Zlen = (EC_GROUP_get_degree(group) + 7)/8;


			ke = EC_KEY_new();
			EC_KEY_set_group(ke, group);
			ret = My_EC_KEY_generate_key(ke);


			ks = EC_KEY_new();
			EC_KEY_set_group(ks, group);
			ret = My_EC_KEY_generate_key(ks);

			switch (eccType)
			{
				case ECCFullUnified:
				{
					my_ec_print_key(out, ks, 0, genValidate);
					my_ec_print_key(out, ke, 1, genValidate);
					
					Z = malloc(Zlen*2);
					Ze = Z;
					Zs = Z + Zlen;
					kavasHashZ(group, Ze, Zlen, qevx, qevy, ke->priv_key);
					kavasHashZ(group, Zs, Zlen, qsvx, qsvy, ks->priv_key);


					Zlen*= 2;
					break;
				}
					
				case ECCEphemeralUnified:
				{
					my_ec_print_key(out, ke, 1, genValidate);
					
					Z = malloc(Zlen);
					kavasHashZ(group, Z, Zlen, qevx, qevy, ke->priv_key);
					break;
				}

				case ECCOnePassUnified:
				{
					Z = malloc(Zlen*2);
					Ze = Z;
					Zs = Z + Zlen;
					if (isInitiator)
					{
						my_ec_print_key(out, ks, 0, genValidate);
						my_ec_print_key(out, ke, 1, genValidate);
					
						kavasHashZ(group, Ze, Zlen, qsvx, qsvy, ke->priv_key);
						kavasHashZ(group, Zs, Zlen, qsvx, qsvy, ks->priv_key);
					}
					else
					{
						my_ec_print_key(out, ks, 0, genValidate);
						kavasHashZ(group, Ze, Zlen, qevx, qevy, ks->priv_key);
						kavasHashZ(group, Zs, Zlen, qsvx, qsvy, ks->priv_key);
					}

					Zlen*= 2;

					break;
				}

				case ECCOnePassDH:
				{
					Z = malloc(Zlen);
					if (isInitiator)
					{	
						my_ec_print_key(out, ke, 1, genValidate);
						kavasHashZ(group, Z, Zlen, qsvx, qsvy, ke->priv_key);
					}
					else
					{
						my_ec_print_key(out, ks, 0, genValidate);
						kavasHashZ(group, Z, Zlen, qevx, qevy, ks->priv_key);
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


			keySize = curve_cfg[param_set].hmacKeyBitSize/8;
			dkm = malloc(keySize);
			memset(dkm, 0, keySize);
			kavasKDF(kdfMd, Z, Zlen, oi, oiLen, dkm, keySize);
			myPrintValue("dkm", dkm, keySize);

			
			HMAC(curve_cfg[param_set].hmacMD, dkm, keySize, macData, macDataLen, tagOut, &tagOutLen);
			myPrintValue("md", tagOut, tagOutLen);

			if (genValidate)
			{				
				OutputValue("OI", oi, oiLen,out, 0);
				OutputValue("CAVSTag", tagOut, tagOutLen, out, 0);
			}
			else
			{
				fprintf(out, "OILen = %d\n", oiLen);
				OutputValue("OI", oi, oiLen,out, 0);
				fprintf(out, "IUTidLen = %d\n", strlen(IUTid));
				OutputValue("IUTid", IUTid, strlen(IUTid), out, 0);
				OutputValue("DKM", dkm, keySize, out, 0);
				OutputValue("Tag", tagOut, tagOutLen, out, 0);
				OutputValue("Message", macData, macDataLen, out, 0);
			}

			free(oi);

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



