
#define RESP_EOL	"\n"

int hex2bin(const char *in, unsigned char *out);
unsigned char *hex2bin_m(const char *in, long *plen);
int do_hex2bn(BIGNUM **pr, const char *in);
int do_bn_print(FILE *out, const BIGNUM *bn);
int do_bn_print_name(FILE *out, const char *name, const BIGNUM *bn);
int parse_line(char **pkw, char **pval, char *linebuf, char *olinebuf);
int parse_line2(char **pkw, char **pval, char *linebuf, char *olinebuf, int eol);
BIGNUM *hex2bn(const char *in);
int tidy_line(char *linebuf, char *olinebuf);
int copy_line(const char *in, FILE *ofp);
int bint2bin(const char *in, int len, unsigned char *out);
int bin2bint(const unsigned char *in,int len,char *out);
void PrintValue(char *tag, unsigned char *val, int len);
void OutputValue(char *tag, unsigned char *val, int len, FILE *rfp,int bitmode);
void fips_algtest_init(void);
void do_entropy_stick(void);
int fips_strncasecmp(const char *str1, const char *str2, size_t n);
int fips_strcasecmp(const char *str1, const char *str2);

static int no_err;

static void put_err_cb(int lib, int func,int reason,const char *file,int line)
	{
	if (no_err)
		return;
	fprintf(stderr, "ERROR:%08lX:lib=%d,func=%d,reason=%d"
				":file=%s:line=%d\n",
			ERR_PACK(lib, func, reason),
			lib, func, reason, file, line);
	}

static void add_err_cb(int num, va_list args)
	{
	int i;
	char *str;
	if (no_err)
		return;
	fputs("\t", stderr);
	for (i = 0; i < num; i++)
		{
		str = va_arg(args, char *);
		if (str)
			fputs(str, stderr);
		}
	fputs("\n", stderr);
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

/* To avoid extensive changes to test program at this stage just convert
 * the input line into an acceptable form. Keyword lines converted to form
 * "keyword = value\n" no matter what white space present, all other lines
 * just have leading and trailing space removed.
 */


	

/* NB: this return the number of _bits_ read */
int bint2bin(const char *in, int len, unsigned char *out)
    {
    int n;

    memset(out,0,len);
    for(n=0 ; n < len ; ++n)
	if(in[n] == '1')
	    out[n/8]|=(0x80 >> (n%8));
    return len;
    }

int bin2bint(const unsigned char *in,int len,char *out)
    {
    int n;

    for(n=0 ; n < len ; ++n)
	out[n]=(in[n/8]&(0x80 >> (n%8))) ? '1' : '0';
    return n;
    }

/*-----------------------------------------------*/

void PrintValue(char *tag, unsigned char *val, int len)
{
#ifdef VERBOSE
	OutputValue(tag, val, len, stdout, 0);
#endif
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


