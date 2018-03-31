#include "common.c"

#define CIPHER_LIST "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"
#define CAFILE "rootcert.pem"
#define CADIR NULL
#define CERTFILE "newnode.pem"
#define KEYFILE "newnodekey.pem"
#define CSR "newnodereq.pem"
#define CERTIFICATE "newnodecert.pem"
#define CA_CERTIFICATE "ca_cert.pem"
#define LIST "update_list.txt"


struct client *lastnode;

SSL_CTX *setup_client_ctx(void)
{
    SSL_CTX *ctx;
    ctx = SSL_CTX_new(SSLv23_method());
    
    if(SSL_CTX_load_verify_locations(ctx,CAFILE,CADIR) != 1)
        int_error("Error loading CA file");
        
    if(SSL_CTX_set_default_verify_paths(ctx) != 1)
        int_error("Error loading default CA file");    
    
    if(SSL_CTX_use_certificate_chain_file(ctx,CERTFILE) != 1)
        int_error("Error loading certificate from file");
        
    if(SSL_CTX_use_PrivateKey_file(ctx,KEYFILE,SSL_FILETYPE_PEM) != 1)
        int_error("Error loading private key from file");
    
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER, verify_callback);
    SSL_CTX_set_verify_depth(ctx,4);
    SSL_CTX_set_options(ctx,SSL_OP_ALL|SSL_OP_NO_SSLv2);
    if(SSL_CTX_set_cipher_list(ctx, CIPHER_LIST) != 1)
        int_error("Error setting cipher list (no valid ciphers)");
    return ctx;
}

int verify()
{
    //struct stat st1;
    //verify signed cert
    char test[100]; 
    snprintf(test,sizeof(test),"openssl x509 -in %s -pubkey -noout -outform pem | sha256sum > verifycert",CERTIFICATE);
    system(test);
    memset(&test[0],0,sizeof(test));
    snprintf(test,sizeof(test),"openssl req -in %s -pubkey -noout -outform pem | sha256sum > verifycsr",CSR);    
    system(test);
    memset(&test[0],0,sizeof(test));
    
    struct stat st1;
    FILE *fp2 = fopen("verifycert","r");
    stat(CSR,&st1);
    int buff_size = st1.st_size;
    char verifycert[buff_size];
    if(fp2!=NULL)
    {
        size_t fileread = fread(verifycert,sizeof(char),buff_size,fp2);
        if(ferror(fp2))
            fprintf(stderr,"Error reading the file");
        else
            verifycert[fileread++]='\0';
        fclose(fp2);
    }  
    
    
    fp2 = fopen("verifycsr","r");
    stat(CSR,&st1);
    int buff_size1 = st1.st_size;
    char verifycsr[buff_size1];
    if(fp2!=NULL)
    {
        size_t fileread = fread(verifycsr,sizeof(char),buff_size1,fp2);
        if(ferror(fp2))
            fprintf(stderr,"Error reading the file");
        else
            verifycsr[fileread++]='\0';
        fclose(fp2);
    }   
    
    if(strcmp(verifycert,verifycsr) == 0)
    {
        
        return 1;
    }
    else
        return 0;

    
}


int issue_cert (SSL *ssl)
{
    int bytesread;
    char test[100];
    //send csr to the server
    struct stat st;
    FILE *fp = fopen(CSR,"r");
    stat(CSR,&st);
    int buff_size = st.st_size;
    char buff[buff_size];
    if(fp!=NULL)
    {
        size_t fileread = fread(buff,sizeof(char),buff_size,fp);
        if(ferror(fp))
            fprintf(stderr,"Error reading the file");
        else
            buff[fileread++]='\0';
        fclose(fp);
    }   
    SSL_write(ssl,buff,strlen(buff));
    //puts(buff);
       
    //receive signed cert from server
    printf("Recieving cert from server\n");
    char cert[5000];
    int certread;
    certread = SSL_read(ssl,cert,sizeof(cert));
    cert[certread] = 0;
    puts(cert);

    //Put cert in .pem file
    FILE *fp1 = fopen(CERTIFICATE,"w+");
    //char buffer[certread];
    fwrite(cert,sizeof(char),certread,fp1);
    fclose(fp1);
    
    //recieve server cert from server
    printf("Recieving server cert from server\n");
    char servcert[5000];
    certread = 0;
    certread = SSL_read(ssl,servcert,sizeof(servcert));
    servcert[certread] = 0;
    puts(servcert);

    //Put cert in .pem file
    fp1 = fopen(CA_CERTIFICATE,"w+");
    //char buffer[certread];
    fwrite(servcert,sizeof(char),certread,fp1);
    fclose(fp1);
    
    int z = verify();
    if(z==1)
    {
        printf("Verified\n");
        snprintf(test,sizeof(test),"cat %s %s %s > %s ",CERTIFICATE, CA_CERTIFICATE, CAFILE, CERTFILE);    
        system(test); 
    }
    else
        printf("Not Verified\n");
        
    return 1;
}


int reissue_cert (SSL *ssl)
{
    int bytesread;
    char test[100];
    //send csr to the server
    struct stat st;
    FILE *fp = fopen(CSR,"r");
    stat(CSR,&st);
    int buff_size = st.st_size;
    char buff[buff_size];
    if(fp!=NULL)
    {
        size_t fileread = fread(buff,sizeof(char),buff_size,fp);
        if(ferror(fp))
            fprintf(stderr,"Error reading the file");
        else
            buff[fileread++]='\0';
        fclose(fp);
    }   
    SSL_write(ssl,buff,strlen(buff));
    //puts(buff);
       
    //receive signed cert from server
    printf("Recieving cert from server\n");
    char cert[5000];
    int certread;
    certread = SSL_read(ssl,cert,sizeof(cert));
    cert[certread] = 0;
    puts(cert);

    //Put cert in .pem file
    FILE *fp1 = fopen(CERTIFICATE,"w+");
    //char buffer[certread];
    fwrite(cert,sizeof(char),certread,fp1);
    fclose(fp1);
    //system("openssl x509 -in Amolikacert1.pem -text");
    
    int z = verify();
    if(z==1)
    {
        printf("Verified\n");
        snprintf(test,sizeof(test),"cat %s %s %s > %s ",CERTIFICATE, CA_CERTIFICATE, CAFILE, CERTFILE);    
        system(test); 
    }
    else
        printf("Not Verified\n");
        
    return 1;
}


int add_new_client (SSL *ssl)
{
    int bytesread;
    //send CERTFILE to the server
    printf("sending certfile for client to check\n");
    struct stat st;
    FILE *fp = fopen(CERTFILE,"r");
    stat(CERTFILE,&st);
    int buff_size = st.st_size;
    char buff[buff_size];
    if(fp!=NULL)
    {
        size_t fileread = fread(buff,sizeof(char),buff_size,fp);
        if(ferror(fp))
            fprintf(stderr,"Error reading the file");
        else
            buff[fileread++]='\0';
        fclose(fp);
    }   
    SSL_write(ssl,buff,strlen(buff));
    //puts(buff);
    
    //read response from server
    bytesread=0;    
    printf("Recieving response from the server\n");
    char buffer[100];
    bytesread = SSL_read(ssl,buffer,sizeof(buffer));
    printf("bytesread : %d\n",bytesread);
    buffer[bytesread] = 0; 
    char response[]="ok";
    printf("recieved from server : ");
    puts(buffer);
    if(strncmp(buffer,response,bytesread)==0)
    {
        printf("Goto reissue fcn\n");
        issue_cert(ssl);          
    }
    else
        printf("rejected\n");
      
    return 0;
}


int update_list(SSL *ssl)
{
    //sending update list to server
    FILE *fp = fopen( LIST,"r");
    struct stat st;
    stat(LIST,&st);
    int buff_size = st.st_size;
    char buffer[buff_size];
    if(fp!=NULL)
    {
        size_t fileread = fread(buffer,sizeof(char),buff_size,fp);
        if(ferror(fp))
            fprintf(stderr,"Error reading the file");
        else
            buffer[fileread++]='\0';
        fclose(fp);
    }
    SSL_write(ssl,buffer,strlen(buffer));
    puts(buffer);

    return 1;
}


int do_client_loop (SSL *ssl)
{
    int byteswritten,err,bytesread;
    
    //receive welcome from the server
    printf("Recieving from server\n");
    char buffer[500];
    bytesread = SSL_read(ssl,buffer,sizeof(buffer));
    buffer[bytesread] = 0;
    puts(buffer);
    
    //write ur choice
    char msg[100]; 
    scanf("%s",msg);
    SSL_write(ssl,msg,strlen(msg));
    char reissue[] = "1";
    char update[] = "2"; 
    char new_client[] = "3"; 
    
    if(strncmp(msg,reissue,strlen(msg))==0)
    {
        printf("You chose reissue fcn\n");
        reissue_cert(ssl);
    }
    else if (strncmp(msg,update,strlen(msg))==0)
    {
        printf("You chose update fcn\n");
        update_list(ssl);
    }
    else if (strncmp(msg,new_client,strlen(msg))==0)
    {
        printf("You chose new_client fcn\n");
        add_new_client(ssl);
    }    
    else
        printf("Invalid choice\n");
    /*
    char choice;
    printf("Do u want to cont? (y/n)?\n");
    scanf("%c",&choice);
    if (choice == 'y')
        do_client_loop(ssl);
    else */   
    return 1;
}


int main(int argc,char *argv[])
{
    BIO *conn;
    SSL *ssl;
    SSL_CTX *ctx;
    
    
    init_OpenSSL();  /// initializing the ssl config files
    //seed_prng();   implement for final program refer pg 114 for use
    
    ctx = setup_client_ctx();
    
    conn = BIO_new_connect( SERVER ":" PORT);
    if(!conn)
        int_error("Error creating connection BIO ");
        
    if(BIO_do_connect(conn) <= 0)
        int_error("Error connectiong to remote machine ");
    
    if(!(ssl = SSL_new(ctx)))
        int_error("Error creating SSL context");
            
    SSL_set_bio(ssl,conn,conn);
    
    if(SSL_connect(ssl) <= 0)
        int_error("Error connecting SSL object");
    
    fprintf(stderr,"SSL Connection Opened \n");
    
    char *nid;
    nid = certificate_parse(ssl);
    char x[50];
    strcpy(x,nid);
    printf(" nid : %s\n",x);
    int z = do_client_loop(ssl);
    if(z==1)
    {
        SSL_shutdown(ssl);
        //fprintf(stderr,"no error in do client loop");
    }    
    else if(z==0)
    {
        SSL_clear(ssl);
        //fprintf(stderr,"error in do client loop");
    }   
            
    fprintf(stderr, "SSL Connection closed \n");
    //printf("CHECKING\n");
    
    SSL_free(ssl);
    SSL_CTX_free(ctx); 

    return 0;
}



