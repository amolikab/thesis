#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/stat.h>

#define LIST "update_list.txt"
#define LIST1 "update.txt"
#define CSR "trialreq.pem"
#define GRPA "usr_cert_grpA"
#define GRPB "usr_cert_grpB"
#define GRPC "usr_cert_grpC"
#define CAFILE "root.pem"
#define CERTIFICATE "trialcert1.pem"


struct client
{
    char serial[200];
    int trust;
    char csr[50];
    struct client *next;
};

struct client *addnode(struct client *clientAll,char *serial,int trust)
{
    struct client *clientA = (struct client*)malloc(sizeof(struct client));
    struct client *p,*r;
    clientAll->next = clientA;
    strcpy(clientA->serial, serial);
    clientA->trust = trust;
    return clientA;
}

struct client* get_client_from_serial(struct client* list,char *serial)
{
    while(list != NULL)
    {
        //printf("Serial: %s  CSR:  Trust: %d\n",list->serial,list->trust);
        if(strcmp(list->serial,serial) == 0)
            return list;
        else
        {
            list = list->next;
        }
        
    }
       
    
}

void print_list(struct client* q)
{
    while(q != NULL)
    {
        printf("Serial: %s  CSR:  Trust: %d\n",q->serial,q->trust);
        q = q->next;
    }
}



void reissue(int client_index)
{
    char grpA[50] = "..100";
    char grpB[50] = "..200";
    char grpC[50] = "..300";
    char test[500];
      
    if(client_index<=30)
    {    //group A
           
        snprintf(test,sizeof(test),"openssl x509 -req -in %s -sha1 -extfile openssl.cnf -extensions %s -CA %s -CAkey %s -CAcreateserial -out %s",CSR,GRPA,CAFILE,CAFILE,CERTIFICATE);
        system(test); 
        memset(&test[0],0,sizeof(test));           
        //system("openssl x509 -in trialcert1.pem -text");
    }    
    else if((client_index>30)&&(client_index<80))
    {   //group B
        snprintf(test,sizeof(test),"openssl x509 -req -in %s -sha1 -extfile openssl.cnf -extensions %s -CA %s -CAkey %s -CAcreateserial -out %s",CSR,GRPB,CAFILE,CAFILE,CERTIFICATE);
        system(test); 
        memset(&test[0],0,sizeof(test));
        //system("openssl x509 -in trialcert1.pem -text");
    }    
    else
    {    //group C
        snprintf(test,sizeof(test),"openssl x509 -req -in %s -sha1 -extfile openssl.cnf -extensions %s -CA %s -CAkey %s -CAcreateserial -out %s",CSR,GRPC,CAFILE,CAFILE,CERTIFICATE);
        system(test); 
        memset(&test[0],0,sizeof(test));
        //system("openssl x509 -in trialcert1.pem -text");
    }  
        
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
            reissue(client_index);
    }
    else if((old_trust>=21)&&(old_trust<80))
    {
        if((client_index<20)||(client_index>=80))
            reissue(client_index);
    }
    else
    {
        if(client_index<80)
            reissue(client_index);
    }
  
}
  

int main(int argc,char *argv[])
{   
    //int serial = 123;
    //int trust = 100;
    char c;
    struct client clientAll,*p,*q,*s;    
    //p = &clientAll;
    struct client *clientA = addnode(p,"123",100);
    struct client *lastnode = clientA;
    q = clientA;
    s = p->next;       
    //printf("Hi ur client A with the following prop\n");
    //printf("Serial: %d  CSR:  Trust: %d\n",clientA->serial,clientA->trust);
    //int serialB = 124;
    //trust = 20;    
    struct client *clientB = addnode(lastnode,"124",20);
    lastnode = clientB;   
    //printf("Hi ur client B with the following prop\n");
    //printf("Serial: %s  CSR:  Trust: %d\n",clientB->serial,clientB->trust);
    
    struct client *clientC = addnode(lastnode,"125",60);
    lastnode = clientC;
    
    struct client *clientD = addnode(lastnode,"126",40);
    lastnode = clientD;
    print_list(s);
    
    //printf(" address clientAll %p\n",p);    
    /*printf("Do you want to add another client?(Y/N)\n");    
     
    scanf("%c",&c);    
    if (c == 'Y')
        {
            printf("Enter serial: ");
            scanf("%d",&serial);
            printf("Enter trust: ");
            scanf("%d",&trust);
            struct client *clientB = addnode(lastnode,serial,trust);
            lastnode = clientB;
        }
    else
        printf("OK\n");
    //struct client* r = get_client_from_serial(clientA,125);
    //printf("serial has a value %d\n",r->trust);  
        
    int choice;
    printf("Enter your option: \n");
    printf("1. Sendng update    2. Re-issue request\n");
    scanf("%d",&choice);
    if(choice == 1)
    {
        
        printf("u selected %d type ur (serial,trust value) of neighbour to update \n",choice);
        scanf("%d %d",&serial_to_update,&update);
        //printf("You typed %d %d\n",serial_to_update,update);
        update_index(update,serial_to_update,informing_serial,s);        
    }
    else if (choice == 2)
    {
        printf("Goto reissue fcn \n");
        //reissue(serial,s);
    }
    //printf("clientB trust changed to : %d\n",clientB->trust);*/
    /*
    int update,serial_to_update;
    int informing_serial = clientA->serial;
    printf("Type ur (serial,trust value) of neighbour to update \n");
    scanf("%d %d",&serial_to_update,&update);
    update_index(update,serial_to_update,informing_serial,s);
    */
    
    //printf("check main\n");
    
    FILE *fp = fopen( LIST,"r");
    struct stat st;
    int fileread;
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
    puts(buffer);
    
    //reading the file from buffer
    int bytesread = buff_size;
    fp = fopen(LIST1,"w+");
    fwrite(buffer,sizeof(char),bytesread,fp);
    fclose(fp);
    
    //printf("check file\n");
    
    fp = fopen(LIST1,"r");
    int update;
    char serial_to_update[200];
    
    //printf("check\n");
    char *informing_serial = clientA->serial;
    //printf("informing serial is %s\n",clientA->serial);
    
    //strcpy( informing_serial, clientA->serial);
    /*if(&informing_serial<0)
    {
        printf("Error copying serial\n");
        exit(1);
    }
    
    printf("informing_serial %s\n",informing_serial);
    /printf("check\n");
    struct client *po = get_client_from_serial(s,informing_serial);
    printf("%s\n",po->serial);
    */
    while(1)
    {
        
        //printf("check in while\n");  
        fscanf(fp,"%s ",serial_to_update);       
        //printf("%s  ",serial_to_update);
        fscanf(fp,"%d ",&update);       
        //printf("%d  \n",update);
        update_index(update,serial_to_update,informing_serial,s);     
        
        if(feof(fp))
            break;        
    }
    fclose(fp);
    /*char choice;
    printf("Do you want to quit? (y/n)\n");
    scanf("%c",choice);
    if(choice == 'y')*/
    
    struct client* curr;
    while((curr = s)!= NULL)
    {
        s = s->next;
        free(curr);    
    }
        
    
    return 0;
}












