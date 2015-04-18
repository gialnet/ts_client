/*

(c) Redmoon Consultores ver 1.0 jun 2013
Author Antonio Perez Caballero


*/


#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/pem.h>
#include <openssl/ts.h>
#include <curl/curl.h>

#define handle_error(msg) \
        do { perror(msg); exit(EXIT_FAILURE); } while (0)


unsigned char hash_bin[EVP_MAX_MD_SIZE];
unsigned int  hash_bin_len;
unsigned char hash_hex[(EVP_MAX_MD_SIZE * 2) + 1];
unsigned char *request;
unsigned long request_len;


size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t written;
    written = fwrite(ptr, size, nmemb, stream);
    return written;
}


int main(int argc, char *argv[])
{

char *filetohash = NULL;
char *fileout = NULL;
char *digest = NULL;
char *default_digest="sha1";
char *default_tsa="http://tss.accv.es:8318/ts";
char *TSAurl = NULL;
char *policy = NULL;
int cert = 0;
int nonce = 0;
int xmlout = 0;


for (argc--, argv++; argc > 0; argc--, argv++)
	{

		if (strcmp(*argv, "-file") == 0)
			{
			argc--;
			if (argc < 1) goto usage;
			filetohash = *++argv;
			}
		else if (strcmp(*argv, "-cert") == 0)
			{
			cert = 1;
			}
		else if (strcmp(*argv, "-nonce") == 0)
			{
			nonce = 1;
			}
		else if (strcmp(*argv, "-digest") == 0)
			{
			argc--;
			if (argc < 1) goto usage;
			digest = *++argv;
			}
		else if (strcmp(*argv, "-out") == 0)
			{
			argc--;
			if (argc < 1) goto usage;
			fileout = *++argv;
			}
		else if (strcmp(*argv, "-tsaurl") == 0)
			{
			argc--;
			if (argc < 1) goto usage;
			TSAurl = *++argv;
			}
		else if (strcmp(*argv, "-policy") == 0)
			{
			argc--;
			if (argc < 1) goto usage;
			policy = *++argv;
			}

		else
			goto usage;

	}



if (filetohash==NULL)
   goto usage;

if (fileout==NULL)
   goto usage;

if (TSAurl==NULL)
   TSAurl=default_tsa;

if (digest==NULL)
    digest=default_digest;


if (hashCreate(digest, filetohash) > 0)
   if ( tsReqCreate(nonce, cert, digest, policy) > 0)
      if (sendTS(TSAurl, fileout) > 0)
	  printf("Was saved %s\n",fileout);

goto cleanup;

usage:

printf("(c) Redmoon Consultores ver 1.0 jun 2013\n"
"Author Antonio Perez Caballero\n"
"usage: tsclient -file -digest -tsaurl -policy -cert -nonce -out\n"
"-file 	file to time stamp\n"
"-digest \n"
"		md4            to use the md4 message digest algorithm\n"
"		md5            to use the md5 message digest algorithm\n"
"		ripemd160      to use the ripemd160 message digest algorithm\n"
"		sha            to use the sha message digest algorithm\n"
"		sha1           to use the sha1 message digest algorithm\n"
"		sha224         to use the sha224 message digest algorithm\n"
"		sha256         to use the sha256 message digest algorithm\n"
"		sha384         to use the sha384 message digest algorithm\n"
"		sha512         to use the sha512 message digest algorithm\n"
"-tsaurl 	url TSA server by default http://tss.accv.es:8318/ts\n"
"-policy 	Submit a policy OID TSA provider otherwise the supplier will send one of his own\n"
"-cert 	 	We call on the authority of time that you return your certificate if omitted did not ask\n"
"-nonce  	Generate a random number\n"
"-out 	 	name of the output file time stamp\n"
"sample:\n"
"tsclient -file mydoc.pdf -out timestamp.tsr \n"
);


cleanup:

free(request);

return 0;

}

//
// Creates hash of the source file
//
int hashCreate(char * hash_alg_c_str, char *filename_c_str) {

	const EVP_MD *md = NULL;
	EVP_MD_CTX mdctx;
	size_t bytes_read = 0;
	char readbuffer[1024];
	char help_buff[3];
	unsigned int i = 0;


	OpenSSL_add_all_digests();

	if ((md = EVP_get_digestbyname(hash_alg_c_str)) == NULL) {
		printf("Hash algorithm not supported");
		return(0);
	}

	EVP_MD_CTX_init(&mdctx);

	if (!EVP_DigestInit_ex(&mdctx, md, NULL)) {
		printf("Unable to init hash context");
		return(0);
	}

	FILE *fr = NULL;
	if ((fr = fopen(filename_c_str, "rb")) == NULL) {
		printf("Unable to open selected file");
		return(0);
	}

	while (!feof(fr)) {

		bytes_read = fread(readbuffer, sizeof(char), 1024, fr);

		if (!EVP_DigestUpdate(&mdctx, readbuffer, bytes_read)) {
			printf("Unable to update hash context");
			return(0);
		}

	}

	if (!EVP_DigestFinal_ex(&mdctx, hash_bin, &hash_bin_len)) {
		printf("Unable to finish hash context");
		return(0);
	}

	EVP_MD_CTX_cleanup(&mdctx);

	if (fclose(fr) == EOF) {
		printf("Unable to close selected file");
		return(0);
	}

	// Create hex representation of the hash
	for (i = 0; i < hash_bin_len; i++) {
		sprintf(help_buff, "%02x", hash_bin[i]);
		memcpy((hash_hex + (2 * i)), help_buff, 2);
	}

	*(hash_hex + (i * 2)) = '\0';

	EVP_cleanup();

	return 1;

}


/*

-no_nonce

    No nonce is specified in the request if this option is given. Otherwise a 64 bit long pseudo-random none is included in the request. 
	It is recommended to use nonce to protect against replay-attacks. 

-cert

    The TSA is expected to include its signing certificate in the response.

*/

int tsReqCreate(long int nonce, int cert, char *hash_alg, char *policy) {

	TS_REQ *ts_req = NULL;

	// Allocate memory for TS_REQ structure
	if ((ts_req = TS_REQ_new()) == NULL) {
		printf("Unable to create request");
		return (0);
	}

	// Set request version
	if (!TS_REQ_set_version(ts_req, 1)) {
		TS_REQ_free(ts_req);
		ts_req = NULL;
		printf("Unable to set request version");
		return (0);
	}

	// Create and add MSG_IMPRINT object
	TS_MSG_IMPRINT *msg_imprint = NULL;
	if ((msg_imprint = TS_MSG_IMPRINT_new()) == NULL) {
		TS_REQ_free(ts_req);
		ts_req = NULL;
		printf("Unable to set message imprint");
		return (0);
	}

	// Add algorithm
	X509_ALGOR *algo = NULL;
	if ((algo = X509_ALGOR_new()) == NULL) {
		TS_REQ_free(ts_req);
		ts_req = NULL;
		TS_MSG_IMPRINT_free(msg_imprint);
		msg_imprint = NULL;
		printf("Unable to set digest algorithm");
		return (0);
	}

	/*
	OBJ_txt2obj() converts the text string s into an ASN1_OBJECT structure. If no_name is 0 then long names and short names will be interpreted as well 		as numerical forms. If no_name is 1 only the numerical form is acceptable. 
	*/
	// hash_alg.c_str() -> sha1
	if (!(algo->algorithm = OBJ_txt2obj(hash_alg, 0))) {
		TS_REQ_free(ts_req);
		ts_req = NULL;
		TS_MSG_IMPRINT_free(msg_imprint);
		msg_imprint = NULL;
		X509_ALGOR_free(algo);
		algo = NULL;
		printf("Unable to set digest algorithm");
		return (0);
	}

	if (!(algo->parameter = ASN1_TYPE_new())) {
		TS_REQ_free(ts_req);
		ts_req = NULL;
		TS_MSG_IMPRINT_free(msg_imprint);
		msg_imprint = NULL;
		X509_ALGOR_free(algo);
		algo = NULL;
		printf("Unable to set digest algorithm");
		return (0);
	}

	algo->parameter->type = V_ASN1_NULL;

	if (!TS_MSG_IMPRINT_set_algo(msg_imprint, algo)) {
		TS_REQ_free(ts_req);
		ts_req = NULL;
		TS_MSG_IMPRINT_free(msg_imprint);
		msg_imprint = NULL;
		X509_ALGOR_free(algo);
		algo = NULL;
		printf("Unable to set digest algorithm");
		return (0);
	}

	// Add digest to imprint
	if (!TS_MSG_IMPRINT_set_msg(msg_imprint, hash_bin, hash_bin_len)) {
		TS_REQ_free(ts_req);
		ts_req = NULL;
		TS_MSG_IMPRINT_free(msg_imprint);
		msg_imprint = NULL;
		X509_ALGOR_free(algo);
		algo = NULL;
		printf("Unable to add digest to message imprint");
		return (0);
	}

	// Add imprint to request
	if (!TS_REQ_set_msg_imprint(ts_req, msg_imprint)) {
		TS_REQ_free(ts_req);
		ts_req = NULL;
		TS_MSG_IMPRINT_free(msg_imprint);
		msg_imprint = NULL;
		X509_ALGOR_free(algo);
		algo = NULL;
		printf("Unable to add message imprint to request");
		return (0);
	}

	// Setting policy
	ASN1_OBJECT *policy_obj = NULL;

	/* por ahora no pasamos la policy */

	if (policy!=NULL) {

		if ((policy_obj = OBJ_txt2obj(policy, 0)) == NULL) {
			TS_REQ_free(ts_req);
			ts_req = NULL;
			TS_MSG_IMPRINT_free(msg_imprint);
			msg_imprint = NULL;
			X509_ALGOR_free(algo);
			algo = NULL;
			ASN1_OBJECT_free(policy_obj);
			policy_obj = NULL;
			printf("Unable to convert policy");
			return (0);
		}

		if (!TS_REQ_set_policy_id(ts_req, policy_obj)) {
			TS_REQ_free(ts_req);
			ts_req = NULL;
			TS_MSG_IMPRINT_free(msg_imprint);
			msg_imprint = NULL;
			X509_ALGOR_free(algo);
			algo = NULL;
			ASN1_OBJECT_free(policy_obj);
			policy_obj = NULL;
			printf("Unable to set policy");
			return (0);
		}

	}


	// Set nonce
	if (nonce != 0) {

		ASN1_INTEGER *asn_nonce = NULL;
		if ((asn_nonce = ASN1_INTEGER_new()) == NULL) {
			TS_REQ_free(ts_req);
			ts_req = NULL;
			TS_MSG_IMPRINT_free(msg_imprint);
			msg_imprint = NULL;
			X509_ALGOR_free(algo);
			algo = NULL;
			ASN1_OBJECT_free(policy_obj);
			policy_obj = NULL;
			printf("Unable to convert nonce to ASN.1");
			return (0);
		}

		if (!ASN1_INTEGER_set(asn_nonce, nonce)) {
			TS_REQ_free(ts_req);
			ts_req = NULL;
			TS_MSG_IMPRINT_free(msg_imprint);
			msg_imprint = NULL;
			X509_ALGOR_free(algo);
			algo = NULL;
			ASN1_OBJECT_free(policy_obj);
			policy_obj = NULL;
			printf("Unable to convert nonce to ASN.1");
			return (0);
		}

		if (!TS_REQ_set_nonce(ts_req, asn_nonce)) {
			TS_REQ_free(ts_req);
			ts_req = NULL;
			TS_MSG_IMPRINT_free(msg_imprint);
			msg_imprint = NULL;
			X509_ALGOR_free(algo);
			algo = NULL;
			ASN1_OBJECT_free(policy_obj);
			policy_obj = NULL;
			ASN1_INTEGER_free(asn_nonce);
			asn_nonce = NULL;
			printf("Unable to set nonce");
			return (0);
		}

		ASN1_INTEGER_free(asn_nonce);
		asn_nonce = NULL;

	}

	// Setting certificate request flag
	if (!TS_REQ_set_cert_req(ts_req, cert)) {
		TS_REQ_free(ts_req);
		ts_req = NULL;
		TS_MSG_IMPRINT_free(msg_imprint);
		msg_imprint = NULL;
		X509_ALGOR_free(algo);
		algo = NULL;
		ASN1_OBJECT_free(policy_obj);
		policy_obj = NULL;
		printf("Unable to set certificate request flag");
		return (0);
	}

	// Convert TS_REQ structure into DER format
	BIO *bio = NULL;
	if ((bio = BIO_new(BIO_s_mem())) == NULL) {
		printf("Unable to create BIO for request output");
		return (0);
	}

	if (!i2d_TS_REQ_bio(bio, ts_req)) {
		printf("Unable to convert request to DER");
		return (0);
	}

	// Get request data out of TS_REQ structure
	BUF_MEM *bptr = NULL;
	BIO_get_mem_ptr(bio, &bptr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free(bio);


	// allocate memory for the request
	request = (unsigned char*) malloc(bptr->length);

	if (request == NULL) {
		printf("Not enough memory");
		return (0);
	}
	memcpy(request, bptr->data, bptr->length);
	request_len = bptr->length;

	// Free everything
	TS_REQ_free(ts_req);
	ts_req = NULL;
	TS_MSG_IMPRINT_free(msg_imprint);
	msg_imprint = NULL;
	X509_ALGOR_free(algo);
	algo = NULL;
	ASN1_OBJECT_free(policy_obj);
	policy_obj = NULL;

	return 1;

}


/*

Send ts request via libcurl

*/

int sendTS(char *url, char *fileout)
{


  CURL *curl;
  CURLcode res;
  struct curl_slist *slist=NULL;

  FILE *outfile;


  outfile = fopen(fileout,"wb");


  slist = curl_slist_append(slist, "Content-Type: application/timestamp-query");

  curl = curl_easy_init();

  if(curl) {

    curl_easy_setopt(curl, CURLOPT_URL, url);

    /* example.com is redirected, so we tell libcurl to follow redirection */
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

    /* some servers don't like requests that are made without a user-agent
     field, so we provide one */ 
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (char *)request);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, request_len);


    /* capturing the response */

    curl_easy_setopt(curl, CURLOPT_WRITEDATA, outfile);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
 
    /* Perform the request, res will get the return code */
    res = curl_easy_perform(curl);

    /* Check for errors */
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));

    /* always cleanup */
    curl_easy_cleanup(curl);
  }

  fclose(outfile);

  return 1;
}
