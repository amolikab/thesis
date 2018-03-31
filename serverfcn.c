

#define CIPHER_LIST "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"
#define CAFILE "rootcert.pem"
#define CADIR NULL
#define CERTFILE "server.pem"
#define KEYFILE "serverkey.pem"
#define CLIENT_CSR "client_csr.pem"
#define CLIENT_CERT "client_cert.pem"
#define CERT_CHAIN "cert_chain.pem"
#define CERTIFICATE "servercert.pem"
#define LIST1 "update.txt"


SSL_CTX *setup_server_ctx(void)
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
    
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,verify_callback);
    
    SSL_CTX_set_verify_depth(ctx,4);
    SSL_CTX_set_options(ctx,SSL_OP_ALL|SSL_OP_NO_SSLv2);
    if(SSL_CTX_set_cipher_list(ctx, CIPHER_LIST) != 1)
        int_error("Error setting cipher list (no valid ciphers)");
        
    return ctx;

}


void get_serial_of_peer(SSL *ssl, char *buff)
{
    X509 *cert = SSL_get_peer_certificate(ssl);
    ASN1_INTEGER *serial = X509_get_serialNumber(cert);
    BIGNUM *bn = ASN1_INTEGER_to_BN(serial,NULL);
    char *tmp = BN_bn2hex(bn);      
    strcpy(buff,tmp);
    BN_free(bn);
    OPENSSL_free(tmp);
}

void get_serial_from_cert(SSL *ssl, char *buff,char * pem_file)
{
    
    char file[100];
    strcpy(file,pem_file);
    FILE *fp = fopen(file,"r");
    X509 *cert = PEM_read_X509(fp,NULL,NULL,NULL);
    ASN1_INTEGER *serial = X509_get_serialNumber(cert);
    BIGNUM *bn = ASN1_INTEGER_to_BN(serial,NULL);
    char *tmp = BN_bn2hex(bn);      
    strcpy(buff,tmp);
    BN_free(bn);
    OPENSSL_free(tmp);

}


int verify_TCA(void)
{
    //extract TCA cert to check the trust index
    FILE *fp,*fp_tca;
    int i = 0,j=0;
    fp = fopen(CERT_CHAIN,"r");
    char line[256];
    while(fgets(line,sizeof(line),fp))
    {
        if(line[0] == '-')
            i++;
    } 
    fclose(fp);
    fp_tca = fopen("TCA_cert.pem","w+");
    fp = fopen(CERT_CHAIN,"r");
    while(fgets(line,sizeof(line),fp))
    {
        if(line[0] == '-')
            j++;
        if( (j>2)    &&  (j<=4)  )    
            fprintf(fp_tca,"%s",line);         
    } 
    fclose(fp);
    fclose(fp_tca);
    
    char *nid;
    nid = pem_certificate_parse("TCA_cert.pem");
    char x[50];
    strcpy(x,nid);
    printf(" nid : %s\n",x);
    //system("rm TCA_cert.pem cert_chain.pem");
          
    if ( ((strcmp(x,"..200"))==0) || ((strcmp(x,"..300")) ==0)     )
        return 1;          
    else if (strcmp(x,"..100") == 0)
        return 0;    
    else
        return -1;  
    
}


int reissue_cert(SSL *ssl)
{
    FILE *fp;
    int bytesread;
    //read csr from the client
    printf("Recieving from the client\n");
    char buffer[800];
    bytesread = SSL_read(ssl,buffer,sizeof(buffer));
    buffer[bytesread] = 0;        
    //Put csr in .pem file
    fp = fopen(CLIENT_CSR,"w+");
    fwrite(buffer,sizeof(char),bytesread,fp);
    fclose(fp);
    puts(buffer);
       
    //find the serial num
    char serial[500];
    get_serial_of_peer(ssl, serial);
    puts(serial);   
     
    
    //send signed cert to the client
    char test[500]; 
    snprintf(test,sizeof(test),"openssl x509 -req -in %s -passin pass:serverkey -sha1 -extfile myopenssl.cnf -extensions usr_cert_grpC -CA %s -CAkey %s -set_serial 0x%s -out %s",CLIENT_CSR,CERTFILE,KEYFILE,serial,CLIENT_CERT);
    system(test);
        
        
    struct stat st;
    FILE *fp1 = fopen(CLIENT_CERT,"r");
    stat(CLIENT_CERT,&st);
    int buff_size = st.st_size;
    char cert[buff_size];
    if(fp!=NULL)
    {
        size_t fileread = fread(cert,sizeof(char),buff_size,fp1);
        if(ferror(fp1))
            fprintf(stderr,"Error reading the file");
        else
            cert[fileread++]='\0';
        fclose(fp1);
    }
    
    SSL_write(ssl,cert,buff_size);
    
    //puts(cert);
    //system("openssl x509 -in Amolikacert.pem -text");

    return 1;
}

int issue_cert(SSL *ssl)
{
    FILE *fp;
    int bytesread;
    //read csr from the client
    printf("Recieving csr from the client\n");
    char buffer[800];
    bytesread = SSL_read(ssl,buffer,sizeof(buffer));
    buffer[bytesread] = 0;        
    //Put csr in .pem file
    fp = fopen(CLIENT_CSR,"w+");
    fwrite(buffer,sizeof(char),bytesread,fp);
    fclose(fp);
    puts(buffer);
        
    //send signed cert to the client
    char test[500]; 
    snprintf(test,sizeof(test),"openssl x509 -req -in %s -passin pass:serverkey -sha1 -extfile myopenssl.cnf -extensions usr_cert_grpB -CA %s -CAkey %s -CAcreateserial -out %s",CLIENT_CSR,CERTFILE,KEYFILE,CLIENT_CERT);
    system(test);
        
    printf("sending signed cert to client\n");    
    struct stat st;
    FILE *fp1 = fopen(CLIENT_CERT,"r");
    stat(CLIENT_CERT,&st);
    int buff_size = st.st_size;
    char cert[buff_size];
    if(fp1!=NULL)
    {
        size_t fileread = fread(cert,sizeof(char),buff_size,fp1);
        if(ferror(fp1))
            fprintf(stderr,"Error reading the file");
        else
            cert[fileread++]='\0';
        fclose(fp1);
    }
    
    SSL_write(ssl,cert,buff_size);
    
    //puts(cert);
    
    //sending own cert to client
    
    FILE *fp2 = fopen(CERTIFICATE,"r");
    stat(CERTIFICATE,&st);
    int buff_size1 = st.st_size;
    char selfcert[buff_size1];
    if(fp2!=NULL)
    {
        size_t fileread1 = fread(selfcert,sizeof(char),buff_size1,fp2);
        if(ferror(fp2))
            fprintf(stderr,"Error reading the file");
        else
            selfcert[fileread1++]='\0';
        fclose(fp2);
    }
    
    SSL_write(ssl,selfcert,buff_size1);
    
    //puts(selfcert);
    
    return 1;
}


int add_new_client(SSL *ssl)
{
    FILE *fp;
    int bytesread;
    //read csr from the client
    printf("Recieving CERTFILE from the client\n");
    char buffer[10000];
    bytesread = SSL_read(ssl,buffer,sizeof(buffer));
    buffer[bytesread] = 0;        
    //Put cert chain in .pem file
    fp = fopen(CERT_CHAIN,"w+");
    fwrite(buffer,sizeof(char),bytesread,fp);
    fclose(fp);
    //puts(buffer);
    int i = verify_TCA();
    if(i == 1)
    {
        printf("Trusted TCA, will sign and add as client\n");
        //respond to client
        char msg[] = "ok";    
        SSL_write(ssl,msg,strlen(msg));
        puts(msg);
      
        issue_cert(ssl);
        char serial[100];
        get_serial_from_cert(ssl,serial,"client_cert.pem");
       
        struct client *clientA = addnode(lastnode,serial,200); 
        struct client *clientB = addnode(lastnode,"124",200);  
        struct client *clientC = addnode(lastnode,"125",200);
        print_list(p->next);
        struct client *client_to_update = get_client_from_serial(p,serial);
        printf("client_to_update->trust : %d\n",client_to_update->trust);
        
        /*printf("Trusted TCA, will sign and add as client\n");
        printf("value of p is %p\n",p);
        printf("value of lastnode is %p\n",lastnode);
        struct client *clientA = addnode(lastnode,"123",100);
        printf("clientA->trust %d\n",clientA->trust);
        printf("value of p is %p\n",p);
        printf("value of clientA is %p\n",clientA);
        printf("value of lastnode is %p\n",lastnode);
        struct client *clientB = addnode(lastnode,"124",20);
        printf("value of p is %p\n",p);
        printf("value of clientB is %p\n",clientB);
        printf("value of lastnode is %p\n",lastnode);
        //print_list(p->next);
        */       
    }
    else if(i == 0)
        printf("Cannot sign as TCA is not trusted enough\n");
    else
        printf("Invalid trust index\n");
    
    
    return 0;
}


void update_index(int update,char *serial_to_update,char *informing_serial,struct client* list )
{
    //printf("check\n");
    struct client *client_to_update = get_client_from_serial(list,serial_to_update);
                                              // get the struct clientB using serialB
    struct client *informing_client = get_client_from_serial(list,informing_serial);
                                              // get the struct clientA using serial
    //print_list(list);
    int informing_trust = informing_client->trust;
    int trust_to_update = client_to_update->trust;
    printf("trust_to_update %d\n",trust_to_update);
    
    int old_trust = client_to_update->trust;
    int client_index = (0.8 * trust_to_update) + (0.2 * update) ;
    client_to_update->trust = client_index;
    //printf("check\n");
    
    if(old_trust<20)
    {
        if(client_index>20)
            printf("reissue\n");
            //reissue(client_index);
    }
    else if((old_trust>=21)&&(old_trust<80))
    {
        if((client_index<20)||(client_index>=80))
            printf("reissue\n");
            //reissue(client_index);
    }
    else
    {
        if(client_index<80)
            printf("reissue\n");
            //reissue(client_index);
    }
  
}
  


int update_list(SSL *ssl)
{
    //receive the file from client
    printf("Recieving the file from client\n");
    char buff[1000];
    int bytesread = SSL_read(ssl,buff,sizeof(buff));
    buff[bytesread] = 0;
    puts(buff);  
    //put the contents in a file
    FILE *fp = fopen(LIST1,"w+");
    fwrite(buff,sizeof(char),bytesread,fp);
    fclose(fp);

    fp = fopen(LIST1,"r");
    int update;
    char serial_to_update[200];
    char informing_serial[100];
    get_serial_from_cert(ssl,informing_serial,"client_cert.pem");
    while(1)
    {
        
        //printf("check in while\n");  
        fscanf(fp,"%s ",serial_to_update);       
        //printf("%s  ",serial_to_update);
        fscanf(fp,"%d ",&update);       
        //printf("%d  \n",update);
        update_index(update,serial_to_update,informing_serial,p);     
        
        if(feof(fp))
            break;        
    }
    fclose(fp);
    print_list(p->next);


    return 1;
}



int do_server_loop(SSL *ssl)
{
    //printf("value of p is %p\n",p);
    //printf("value of lastnode is %p\n",lastnode);
    int bytesread, err,x,byteswritten,bytesread1;  
    
    //write to client
    char msg[] = "Welcome to the Server!  Choose your option 1. Re-issue 2. Update 3. New Client and want a certificate signed";    
    SSL_write(ssl,msg,strlen(msg));
    puts(msg);
      
    
    //receive choice from the client
    printf("Recieving from client\n");
    char buff[100];
    bytesread1 = SSL_read(ssl,buff,sizeof(buff));
    buff[bytesread1] = 0;
    puts(buff);  
    char reissue[] = "1";
    char update[] = "2";  
    char new_client[] = "3";
    
    if(strncmp(buff,reissue,bytesread1)==0)
    {
        printf("Goto reissue fcn\n");
        reissue_cert(ssl);          
    }
    else if (strncmp(buff,update,bytesread1)==0)
    {
        printf("Goto update fcn\n");
        update_list(ssl);        
    }
    else if (strncmp(buff,new_client,bytesread1)==0)
    {
        printf("Goto add_new_client fcn\n");
        add_new_client(ssl);
    }    
    else
        printf("choose better\n");
        
    
    return (SSL_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) ? 1:0;

}


