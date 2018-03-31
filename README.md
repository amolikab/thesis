# thesis

certificates
client:       cert signed by a TCA which is signed by root
              CAFILE :  rootcert //cert trusted by this node and used to verify connections attempting to connect to it.
              CERTFILE: cat newnodecert.pem TCAcert.pem rootcert.pem > newnode.pem // loads the chain of certificates that will be used during SSL connection

              
server:         cert signed by rootcert
                CAFILE : rootcert
                CERTFILE: cat servercert.pem rootcert.pem




client  ------>  server

request to re-issue
send updates about neighbours



client <-------- server

request to send csr to re-issue cert incase of class change due to updates


