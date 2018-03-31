#include<openssl/bio.h>
#include<openssl/err.h>
#include<openssl/rand.h>
#include<openssl/ssl.h>
#include<openssl/x509v3.h>
#include<pthread.h>
#include<sys/stat.h>
#include <stdio.h>

#define THREAD_CC
#define THREAD_TYPE pthread_t
//#define THREAD_CREATE(tid,entry,arg) pthread_create(&(tid),NULL,entry,arg)
#define PORT "6001"
#define SERVER "127.0.0.1"
#define CLIENT 

void handle_error(const char *file, int lineno, const char *msg);

#define int_error(msg) handle_error(__FILE__, __LINE__, msg)

void init_OpenSSL(void);
int verify_callback(int ok, X509_STORE_CTX *store);
char *certificate_parse(SSL *ssl);
char * pem_certificate_parse(char * pem_file);

struct client
{
    char serial[200];
    int trust;
    char csr[50];
    struct client *next;
};
struct client *addnode(struct client *clientAll,char *serial,int trust);
void print_list(struct client* q);
struct client* get_client_from_serial(struct client* list,char *serial);
extern struct client *p;
extern struct client *lastnode;









