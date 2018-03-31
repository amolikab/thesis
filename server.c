//Root key pass phrase: rootkey ; challenge password : challenge
//Client key pass phrase : clientkey ; challenge password : challenge
//server CA key pass phrase : serverCAkey ; challenge password : challenge
//server key pass phrase : serverkey ; challenge password : challenge

#include "common.c"
#include "serverfcn.c"

struct client *p;
struct client *lastnode;


void server_thread(SSL *ssl)
{
    //SSL *ssl = (SSL *)arg;
    //pthread_detach(pthread_self());
    
    if (SSL_accept(ssl) <= 0)
        int_error ("Error accepting SSL connection");
    
    fprintf(stderr,"SSL Connection Opened \n");
    /*
    char *nid;
    nid = certificate_parse(ssl);
    char x[50];
    strcpy(x,nid);
    printf(" nid : %s\n",x);
    */
    
    if(do_server_loop(ssl))
        SSL_shutdown(ssl);
    else
        SSL_clear(ssl);    
    
    fprintf(stderr,"SSL Connection Closed \n");
    
    SSL_free(ssl);
    ERR_remove_state(0);
    
}


int main(int argc, char* argv[])
{
    struct client list;
    p = &list;
    p->next = NULL;
    lastnode = p;
    printf("value of p is %p\n",p);
    printf("value of lastnode is %p\n",lastnode);
    BIO *bio,*client;
    SSL *ssl;
    SSL_CTX *ctx;
    THREAD_TYPE tid[10];
    char choice;
    int i = 0;
    
    init_OpenSSL();
    //seed_prng()
    
    ctx = setup_server_ctx();
    //system("ls");
    
    bio = BIO_new_accept(PORT);
    if(!bio)
        int_error("Error creating server socket");
        
    if(BIO_do_accept(bio) <= 0)
        int_error("Error binding server socket");
    /*
    for(;;)
    {
        
        if(BIO_do_accept(bio) <= 0)
            int_error("Error accepting connection");
    
        client = BIO_pop(bio);
        
        if(!(ssl = SSL_new(ctx)))
            int_error("Error creating SSL context");
        
        SSL_set_bio(ssl,client,client);    
        
        pthread_create(&tid[i], NULL,&server_thread, ssl);  
        i++;
        printf("Press n to exit\n");
        choice = getchar();
        printf("You have selected %c\n",choice);
        if(choice == 'n')
            break;
        else
            printf("wait for another client\n");
        
         
    }
    //make sure thread join the main thread after they are finished
    for(int j = 0; j<i; j++)
        pthread_join(tid[j],NULL);
    */
    while(i<3)
    {
    if(BIO_do_accept(bio) <= 0)
        int_error("Error accepting connection");
    
    client = BIO_pop(bio);
        
    if(!(ssl = SSL_new(ctx)))
        int_error("Error creating SSL context");
      
    SSL_set_bio(ssl,client,client);    
       
    server_thread(ssl);
    //pthread_create(&tid[i], NULL,&server_thread, ssl); 
    i++;
    }
    
    SSL_CTX_free(ctx);
    BIO_free(bio);

    struct client* curr;
    struct client* s = p->next;
    while((curr = s)!= NULL)
    {
        s = s->next;
        free(curr);    
    }
    
    return 0;
}










