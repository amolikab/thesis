
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/stat.h>
#include<openssl/bio.h>
#include<openssl/err.h>
#include<openssl/rand.h>
#include<openssl/ssl.h>
#include<openssl/x509v3.h>
#include<pthread.h>
#include<sys/stat.h>
#include <stdio.h>

void pem_certificate_parse(char *pem_file)
{
    char file[100];
    strcpy(file,pem_file);
    //printf("%s\n",file);
    FILE *fp = fopen(file,"r");
    X509 *cert = NULL;
    cert = PEM_read_X509(fp,NULL,NULL,NULL);
    
    if(cert == NULL)
        printf("Peer did not present a certificate");
       
    char *subj = X509_NAME_oneline(X509_get_subject_name(cert),NULL,0);
    char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert),NULL,0);
    
    printf("Subject : %s \n",subj);
    printf("Issuer : %s \n",issuer);
    
    //to extract other extensions of the certificates
    STACK_OF(X509_EXTENSION) *ext = cert->cert_info->extensions;
    
    int num; //number of extensions
    char *data;
    if(ext)
        num = sk_X509_EXTENSION_num(ext);
    else
        num =0;
    
    if(num<0)
        printf("error parsing number of extensions");
    
    for(int i = 0; i<num; i++)
    {
        X509_EXTENSION *ex = sk_X509_EXTENSION_value(ext,i);
        if( ex == NULL)
            printf("Unable to extract extensions from the stack");
        
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);    
        if( obj== NULL)
            printf("Unable to ASN1 object from extension");
        
        BIO *ext_bio = BIO_new(BIO_s_mem());
        if(ext_bio==NULL)
            printf("unable to allocate mem for ext bio");
            
        if(!X509V3_EXT_print(ext_bio,ex,0,0))
            M_ASN1_OCTET_STRING_print(ext_bio,ex->value);
            
        BUF_MEM *bptr;
        BIO_get_mem_ptr(ext_bio,&bptr);
        BIO_set_close(ext_bio,BIO_NOCLOSE);
        
        BIO_free(ext_bio);
        
        int EXTNAME_LEN =100;
        
        unsigned nid = OBJ_obj2nid(obj);
        if(nid == NID_undef)
        {
            char extname[EXTNAME_LEN]; 
            OBJ_obj2txt(extname,EXTNAME_LEN,(const ASN1_OBJECT *)obj,1);
            printf("Ext name is %s",extname);   
            printf(" with value : %s\n",bptr->data);
            data = bptr->data;            
        }       
    }
    //return data;
       
    /*char y[50];
    strcpy(y,data);
    printf("inside y %s\n",y);*/
    //strcpy(x,y);
    //printf("inside x %s\n",x);
    
    //InvestigateTrust(x);
    printf("Back to certificate parse\n");
}


int main(int argc, char* argv[])
{
    /*
    //code to write from a file to a buffer to a file again
    struct stat st;
    FILE *fp = fopen("clientreq.pem","r");
    stat("clientreq.pem",&st);
    int buff_size = st.st_size;
    char buff[buff_size];
    int byteswritten,err,bytesread;
    printf("buff_size is %d",buff_size);
    if(fp!=NULL)
    {
        size_t fileread = fread(buff,sizeof(char),buff_size,fp);
        if(ferror(fp))
            fprintf(stderr,"Error reading the file");
        else
            buff[fileread++]='\0';
        fclose(fp);
    }
    fwrite(buff,1,buff_size,stdout);
    
    fp = fopen("Amolika.pem","w+");
    fwrite(buff,sizeof(char),700,fp);
    */
    
    //code to strip the last cert of the cert chain to verify if signed by correct root
    
    struct stat st;
    FILE *fp,*fp1,*fp2,*fp_tca;
    int i = 0,j=0;
    fp = fopen("newnode.pem","r");
    stat("newnode.pem",&st);
    int buff_size = st.st_size;
    char line[256];
    while(fgets(line,sizeof(line),fp))
    {
        if(line[0] == '-')
            i++;
    } 
    fclose(fp);
    fp_tca = fopen("TCA_cert.pem","w+");
    fp1 = fopen("first_cert.pem","w+");
    fp2 = fopen("rest_chain.pem","w+");
    //fp3 = fopen("last_cert.pem","w+");
    fp = fopen("newnode.pem","r");
    while(fgets(line,sizeof(line),fp))
    {
        if(line[0] == '-')
        {
            printf("%s",line);
            j++;
        } 
        if(j<=2)
            fprintf(fp1,"%s",line);
        if( (j>2)    &&  (j<=4)  )    
            fprintf(fp_tca,"%s",line);
        if((j>2) && (j<=(i-2)))
            fprintf(fp2,"%s",line);
        //if(j > (i-2))
            //fprintf(fp3,"%s",line);  
    } 
    fclose(fp);
    fclose(fp1);
    fclose(fp2);
    //fclose(fp3);
    fclose(fp_tca);
    //system("cat rest_chain.pem rootcert.pem > verify_chain.pem");
    //system("openssl verify -CAfile verify_chain.pem clientAcert.pem");
    
    /*char *nid;
    nid = certificate_parse(ssl);
    char x[50];
    strcpy(x,nid);
    printf(" nid : %s\n",x);
    */
    printf(" buff_size : %d\n",buff_size);
    char x[50] = "..300";
    
    if ( ((strcmp(x,"..200"))==0) || ((strcmp(x,"..300")) ==0)     )
        printf("Trusted TCA, will sign\n");           
    
    else if (strcmp(x,"..100") == 0)
        printf("Cannot sign as TCA is not trusted enough\n");
    else
        printf("Cannot recognize the trust index\n");
    
    
    //pem_certificate_parse("TCA_cert.pem");
    
    system("openssl x509 -in TCA_cert.pem -serial -noout > serial");
    fp = fopen("serial","r");
    stat("serial",&st);
    buff_size = st.st_size;
    printf("buff_size %d\n",buff_size);
    char c;    
    int n = 0;
    char buff[buff_size];
    int flag = 0;
    while((c = fgetc(fp))!=EOF)
    {
        if(flag == 1)
        {
            buff[n] = (char) c;
            n++;
        }
        if(c == '=')
            flag = 1;       
    }
    buff[n]='\0';
    puts(buff);
    printf("n = %d\n",n);
    
    char serial[n+1];
    strcpy(serial,buff);
    puts(serial);
    
    return 0;
}














