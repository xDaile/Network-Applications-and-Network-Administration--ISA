#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
//#include <ifaddrs.h>
#include <pcap/pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <math.h>
#include <errno.h>
#include <error.h>
#include <syslog.h>
#include <signal.h>


typedef int bool;

#define true 1
#define false 0

#define SOLICIT_MSG_TYPE 1
#define ADVERTISE_MSG_TYPE 2
#define REQUEST_MSG_TYPE 3
#define REPLY_MSG_TYPE 7
#define RELAY_FORW_MSG_TYPE 12
#define RELAY_REPLY_MSG_TYPE 13
#define OPTION_RELAY_MSG 9
#define CLIENT_LINKLAYER_ADDR 79
#define OPTION_INTERFACE_ID 18
#define REMOTE_ID 37
#define IA_NA_OPT 3
#define RELAY_FORW_HOP_COUNT_SIZE 1
#define RELAY_FORW_MSG_TYPE_SIZE 1
#define IA_ID_SIZE 4
#define IA_ID_T_SIZE 4
#define IA_TA_OPT 4
#define IA_PT_OPT 5
#define IA_PD_OPT 8
#define OPTION_IAPREFIX 26
#define PREFERED_LIFETIME_SIZE 4
#define VALID_LIFETIME_SIZE 4
#define PREFIX_LEN_SIZE 1
#define HEX_TO_DEC_CONST 256

#define MSG_TYPE_SIZE 1
#define TRANSACTION_ID_SIZE 3
#define HOP_COUNT_SIZE 1
#define OPTION_RELAY_MSG_SIZE 2
#define OPTION_LEN_SIZE 2
#define LINK_ADDRESS_SIZE 16
#define PEER_ADDRESS_SIZE 16

extern int errno;
int flag_exit=1;
//TO do {
//syslog
//

// //construction to print out the array of the u_char
// for(i=0;i<2;i++)
//   printf("%02X ",part_rel_r->option[i]);
//  printf("\n");
typedef  struct client_server_msgs{
  u_char msq_type;
  u_char transaction_id[3];
  u_char* options;
}msg_form;

typedef struct ipv6Header{
  u_char nothing[8];
  u_char src[LINK_ADDRESS_SIZE];
  u_char not[16];
}myipv6Header;

typedef struct msg_general_format{
  u_char option[2];
  u_char lenght[2];
}msg_gen_form; //for relay reply

typedef  struct relay_msg_repl{
  u_char msg_type;
  u_char hop_count;
  u_char link_addr[16];
  u_char peer_addr[16];
  u_char * rest;
}relay_msg_r;

typedef  struct relay_msg_forw{
  u_char msg_type;
  u_char hop_count;
  u_char link_addr[16];
  u_char peer_addr[16];

  u_char option_relay_msg[2];
  u_char option_len[2];

  u_char client_LL_address[2];
  u_char client_LL_lenght[2];
  u_char client_LL_type[2];
  u_char client_LL_value[6];

  u_char int_id_opt[2];
  u_char int_id_len[2];
  u_char int_id_val[3];
}relay_msg_f;

//function for comparing two 16bytes addresses
int compare_addreses(u_char *ad1, u_char *ad2){
  for(int i=0;i<16;i++){
    if(ad1[i]!=ad2[i]){
      return 1;//NOT SAME
    }
  }
  return 0;
}

void closeEverything(){
  kill(getpid(),SIGKILL);
  flag_exit=0;
}

//function to send message to client
int sendSocketClient(relay_msg_f rel_forw, u_char* message,int msg_size,char* name){
  int i=0;
  int sockfdRet;
  int opt=0;
  u_char * initialize;
  initialize=malloc(sizeof(u_char)*msg_size);
  memcpy(initialize, message,(sizeof(u_char)*(msg_size))); //0

  if( (sockfdRet = socket(AF_INET6,SOCK_DGRAM,0))<0){
    error(1,14,"Error while creating socket\n");
  }
  if(setsockopt(sockfdRet, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,sizeof(opt))){
    error(1,15,"Error during setsockopt\n");
  }
  struct sockaddr_in6 intAddr;
  intAddr.sin6_family=AF_INET6;
  intAddr.sin6_port=htons(546);//or 547?
  intAddr.sin6_flowinfo=1;
  intAddr.sin6_scope_id=if_nametoindex(name);
  for(i=0;i<16;i++)
     intAddr.sin6_addr.s6_addr[i]=rel_forw.link_addr[i];

  struct sockaddr_in6 targAddr;
  targAddr.sin6_family=AF_INET6;
  targAddr.sin6_port=htons(546);//or 547?
  targAddr.sin6_flowinfo=1;
  targAddr.sin6_scope_id=if_nametoindex(name);
  for(i=0;i<16;i++)
     targAddr.sin6_addr.s6_addr[i]=rel_forw.peer_addr[i];//

  if((bind(sockfdRet,(struct sockaddr *)&intAddr,sizeof( intAddr)))==-1){//adress of interface bind
    error(1,16,"Error during bind\n");
  }

   if(sendto(sockfdRet,message,(sizeof(u_char)*(msg_size)),0,(struct sockaddr *)&targAddr,sizeof(targAddr))<0){
     error(1,17,"Error during sendto\n");
   }

  close(sockfdRet);
  free(message);
  free(initialize);
  return 0;
}

int main(int argc, char* argv[])
{
  bool sMark=false,lMark=false,dMark=false,iMark=false;//marks if the argument already was found
  int option;
  int num=0;//value to compare with argc, after getopts using
  char* server;//address of the server that will be relay connected to
  char* interface;//name of the interface that will be captured
  pcap_if_t *dev;
  pcap_if_t **alldevsp;//all the devices
  int *index_int;// list of the indexes of the interfaces
  int index=0;
  pcap_if_t *previous=NULL;  //for filtering devices, and deleting some of them from the list that pcap_findalldevs created,
  pcap_if_t *first=NULL;//for saving the node that will be deleted
  pcap_if_t *toDEL=NULL;//pointer to interface that will be deleted from list
  int i=0;//variable for counting in cycles

  signal(SIGINT,closeEverything);

//Working on arguments, one by one
  while((option = getopt(argc, argv, "s:ldi:")) != -1){
    switch(option){
      case's':
        { if(sMark==true){
            error(1,1,"One argument twice\n");
          }
          sMark=true;
          server=malloc(sizeof(char)*INET6_ADDRSTRLEN);
          if(server==NULL){
              error(1,21,"Malloc Error\n");
          }
          int *result;
          result=malloc(sizeof(int));
          if(result==NULL){
              error(1,21,"Malloc Error\n");
          }
          strcpy(server,optarg);
          //printf("opt\n");
          if (inet_pton(AF_INET6, server, result) != 1)
            {
              error(1,2,"ipv6 address is BAD\n");
            }
          free(result);
          //printf("server: %s\n",server);//DELETE HERE
          num=num+2;
          break;
        }
      case'l':
        {
          if(lMark==true){
            error(1,1,"one argument twice\n");
            }
          lMark=true;
          //printf("syslog spravy zapnute\n");//DELETE HERE
          num++;
          break;
        }
      case'd':
        {
          if(dMark==true){
            error(1,1,"one argument twice\n");
          }
          dMark=true;
          num++;
          break;
        }
      case'i':
        {
          if(iMark==true){
            error(1,1,"one argument twice\n");
          }
          iMark=true;
          interface=malloc(sizeof(optarg));//name of the interface that is scanned
          if(interface==NULL){
              error(1,21,"Malloc Error\n");
          }
          strcpy(interface,optarg);//copy argument to name of the interface
          //printf("interface:%s\n",interface);//DELETE HERE
          num=num+2;
          break;
        }
      default:
        error(1,3,"Unkonown argument\n");
        break;
    }
  }
  //check for the arguments and options that is set
  if((sMark*2+lMark+dMark+iMark*2)!=num || num==0){
      error(1,4,"Error with arguments\n");
    }
  if(!sMark){
    error(1,5,"Missing server argument\n");
  }

  alldevsp=malloc(sizeof(pcap_if_t));
  if(alldevsp==NULL){
      error(1,21,"Malloc Error\n");
  }
  char errbuf[PCAP_ERRBUF_SIZE];
  //find all the devices
  pcap_findalldevs(alldevsp, errbuf);

  //assign the first one device because of cycle
  dev=alldevsp[0];



  //INDEX of the interface
  index_int=(int*)malloc(sizeof(int));
  if(index_int==NULL){
      error(1,21,"Malloc Error\n");
  }

  //searching and deleting some of the items from the list of the interfaces
  for(;dev->next!=NULL;){

    //increase the memory size for the indexes of the interfaces
    index_int=(int*)realloc(index_int, sizeof(int)*(i+1));

    //generate new index for the interface
    index_int[i]=abs((rand()*1000+rand())%99999);
    // printf("generating :: index =%d ,, generated= %d, device %s\n",i,index_int[i],dev->name);
    i++;

    //check if the interface is a loopback interface
    if((dev->flags) & PCAP_IF_LOOPBACK){
      toDEL=dev;
      dev=dev->next;
      free(toDEL);
    }

  //list of the addresses at the current interface
  pcap_addr_t *devInt=dev->addresses;

  bool haveIp6=false;

  //searching and going throught list of addresses
  while(devInt!=NULL){

      if(devInt->addr->sa_family==AF_INET6){

  char* res=malloc(sizeof(char)*129);
  struct sockaddr_in6 myAddr;

//relay must have Global address
  inet_ntop(AF_INET6,&(((struct sockaddr_in6*)devInt->addr)->sin6_addr),res,129);
  if(inet_pton(AF_INET6,res,&(myAddr.sin6_addr))!=1){
      error(1,13,"Error in function pton \n");//ALERT HERE ERRNO IS OUT OF DATE
  }
//  if((res[0]!='f') && (res[1]!='e')){
        //printf("int:%s, have on first place %c\n", dev->name, res[0]);
          haveIp6=true;
        //}
      }
      devInt=devInt->next;
  }

  //if interface have ipv6 address save current interface as the interface that is last interface in the list that have ipv6
  if(haveIp6){
      previous=dev;
      if(first==NULL){
          first=dev;
      }
      dev=dev->next;
    }

//if it is not ipv6 interface delete item from list
    else{

      //if the item is not last one in the list
        if((dev->next!=NULL) && (previous!=NULL)){
          previous->next=dev->next;
          toDEL=dev;
          dev=dev->next;
          free(toDEL);
        }
        if((previous==NULL) && (dev->next!=NULL)){
            toDEL=dev;
            dev=dev->next;
            free(toDEL);
        }

        if(dev->next==NULL && previous!=NULL){
          previous->next=NULL;
          }
        if(dev->next==NULL && previous==NULL){
          error(1,6,"Not a single one interface that have ipv6 address\n");
          }
    }
  }

  dev=first;
  int n_of_int=0;
  //count interfaces
  while((dev)!=NULL){
    n_of_int++;
    dev=dev->next;
    }

  dev=first;
  //set the dev(one interface variabile), to the begin of the list
  //check if there is in the list of interfaces, one that was next to argument -i
  if(iMark)
    {
      iMark=false;
      for(;dev->next!=NULL && iMark==false;dev=dev->next)
      {
              //compare their names
          if(strcmp(dev->name,interface)==0){
            break;
            iMark=true;//found the interface with same name
          }
      }
      if(dev->next==NULL && iMark==false && strcmp(dev->name,interface)!=0){
        error(1,7,"Given interface with argument -i do not exists or do not have ipv6\n");
      }
      iMark=true;
    }
  dev=first;

//CREATE A PROCCES for every interfaces
  bool catchHere=false;
  int childs[n_of_int];//DELETE HERE
  for( i=0;i<n_of_int && iMark==false;i++){
    if((childs[i]=fork())==0)
    {
      catchHere=true;
      int q=0;
      while(q!=i){
        dev=dev->next;
        q++;
      }
      break;
    }
  }
//if we are in procces that have catchHere flag setted, we will open pcap leter in it
   // if(catchHere || iMark ){
   //   printf("Name of the interface that is captured in the child:%s\n\n",dev->name);//DELETE HERE
   // }

  if(catchHere || iMark){
//JOIN MULTICAST
    int s;
  //socket for registration to multicast
    s=socket(AF_INET6,SOCK_DGRAM,0);
    if(s<0){
      error(1,8,"socket creating failed\n");
    }
    pcap_if_t *toMC=NULL;//item in the list of interfaces, we will need another list
  //struct for multicast registration
    struct ipv6_mreq mreq;

//LIST ALL devices, because we need to find the index of the interface that is in the forked procces
    pcap_findalldevs(alldevsp, errbuf);
    toMC=alldevsp[0];
    while(toMC!=NULL){
      if(strcmp(toMC->name,dev->name)==0){
        break;
      }
      index++;
      toMC=toMC->next;
    }
    //struct in6_addr s6;
  //setting multicast address ff02::1:2
    mreq.ipv6mr_multiaddr.s6_addr[0]=0xff;
    mreq.ipv6mr_multiaddr.s6_addr[1]=0x02;
    mreq.ipv6mr_multiaddr.s6_addr[2]=0;
    mreq.ipv6mr_multiaddr.s6_addr[3]=0;
    mreq.ipv6mr_multiaddr.s6_addr[4]=0;
    mreq.ipv6mr_multiaddr.s6_addr[5]=0;
    mreq.ipv6mr_multiaddr.s6_addr[6]=0;
    mreq.ipv6mr_multiaddr.s6_addr[7]=0;
    mreq.ipv6mr_multiaddr.s6_addr[8]=0;
    mreq.ipv6mr_multiaddr.s6_addr[9]=0;
    mreq.ipv6mr_multiaddr.s6_addr[10]=0;
    mreq.ipv6mr_multiaddr.s6_addr[11]=0;
    mreq.ipv6mr_multiaddr.s6_addr[12]=0;
    mreq.ipv6mr_multiaddr.s6_addr[13]=1;
    mreq.ipv6mr_multiaddr.s6_addr[14]=0;
    mreq.ipv6mr_multiaddr.s6_addr[15]=2;
    mreq.ipv6mr_interface=index;

//HERE WE WILL JOIN THE MC GROUP
  if(setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq))<0){
    error(1,9,"setsockopt error while joining multicast\n");
  }
//END JOINING MULTICASTs

//HERE PCAP STARTS
//from here is running procces for every interface that have ipv6 address and also is not loopback, and proces of the parent is running also
//nemal by pockat a ukladat tie processy nejak do pola aby ich potom mohol stopnut pri konci????
}

  if(catchHere || iMark){
    pcap_t *handle;
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    //set filter
    char filter_exp[] = "udp port 546 or 547";//547 potom pre odpoved
    bpf_u_int32 ip=0;
//start capturing packets on device
    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, error_buffer);

    if (handle == NULL) {
        error(1,10,"Could not open %s - %s\n", dev->name, error_buffer);
    }
    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        error(1,11,"Bad filter - %s\n", pcap_geterr(handle));
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        error(1,12,"Error setting filter - %s\n", pcap_geterr(handle));
    }
    //working on captured packets
    struct pcap_pkthdr packet_header; //
    const u_char *packet; //DATA OF PACKET
    //struct ip *my_ip;//my ipv6 structure to get the link addres from the ipv6 header
    struct ether_header *eptr;//same as my_ip just for mac addres of the client
    //const struct udphdr *my_udp;//same as my_ip but with udp_header
    //u_int size_ip;
    while(flag_exit)//Infinite loop because that relay should run still
    {

      //int ether_offset=62;
      //int opt_len=0;
      packet=pcap_next(handle,&packet_header);

      //SOME SEMAFOR should be HERE because i need to copy all the data from received packet,
      //because it is not quaranteed to be valid data by calling next pcap_next in another process
      //printf("\n%s: Packet capture length: %d , total length %d\n",dev->name, packet_header.caplen, packet_header.len);
      eptr=(struct ether_header *)packet;
      char * macAddr=ether_ntoa((const struct ether_addr *)&eptr->ether_shost);
      //printf("\t Source MAC: %s\n",macAddr);
      if(ntohs(eptr->ether_type)!=0x86dd){
        continue;
        printf("Ipv6 packet received\n");//DELETE HERE
      }
      // else{
      //   continue;//NEXT PACKET
      // }

//IPv6 header is fixed size 40, from which i need just 16 bytes, other informations are meaningless for me
    myipv6Header *ipv6H;
    ipv6H=(myipv6Header*)(packet+sizeof(struct ether_header));
  //  opt_len=packet_header.len-sizeof(struct ether_header)-sizeof(struct udphdr)-sizeof(u_char)*(MSG_TYPE_SIZE+TRANSACTION_ID_SIZE)-sizeof(*ipv6H);// , 40 is ipv6

    msg_form *dhcpv6;
    int dhcpv6_offset=sizeof(struct ether_header)+sizeof(struct udphdr)+40;
    int msg_size=packet_header.len-dhcpv6_offset;
    dhcpv6=(msg_form*)(packet+dhcpv6_offset);
    if((dhcpv6->msq_type==SOLICIT_MSG_TYPE) || (dhcpv6->msq_type==REQUEST_MSG_TYPE))
          {
          char *addr;
          u_char *relayed_dhcpv;
          relayed_dhcpv=(u_char*)(packet+dhcpv6_offset);
        //  int rel_size=MSG_TYPE_SIZE+HOP_COUNT_SIZE+LINK_ADDRESS_SIZE+PEER_ADDRESS_SIZE+OPTION_RELAY_MSG_SIZE+OPTION_LEN_SIZE+msg_size;

          //structure that will be sent
          relay_msg_f rel_forw;
          rel_forw.msg_type=RELAY_FORW_MSG_TYPE;
          rel_forw.hop_count=0;
          for(int i=0;i<16;i++){
            rel_forw.peer_addr[i]=ipv6H->src[i];
          }

          pcap_addr_t *brc=dev->addresses;
          bool glob=false;
          u_char local[16];
        //  search among addresess on device, to find ipv6 address to link-addr to message
            while(brc!=NULL){//global ipv6 should be fist in the list
              if(brc->addr->sa_family==AF_INET6)
              {
                addr=malloc(sizeof(char)*129);
                if(addr==NULL){
                    error(1,21,"Malloc Error\n");
                }
                inet_ntop(AF_INET6,&(((struct sockaddr_in6*)brc->addr)->sin6_addr),addr,129);
                struct sockaddr_in6 *adr;
                adr=(struct sockaddr_in6 *)brc->addr;

                if((addr[0]!='f') && (addr[1]!='e')){
                  //->sin6_addr
                  glob=true;
                  for(int i=0;i<16;i++){
                    rel_forw.link_addr[i]=adr->sin6_addr.s6_addr[i];
                  }
                }
                else{
                  for(int i=0;i<16;i++){
                    local[i]=adr->sin6_addr.s6_addr[i];
                  }
                }
              }
              brc=brc->next;
            }
            if(glob==false){
              for(int i=0;i<16;i++){
                rel_forw.link_addr[i]=local[i];
              }
            }
        rel_forw.option_relay_msg[1]=9;
        rel_forw.option_relay_msg[0]=0;
        rel_forw.option_len[1]=msg_size%HEX_TO_DEC_CONST;
        rel_forw.option_len[0]=round((msg_size/HEX_TO_DEC_CONST)%HEX_TO_DEC_CONST);
        rel_forw.client_LL_address[1]=79;
        rel_forw.client_LL_address[0]=0;
        rel_forw.client_LL_lenght[1]=2+6;//6 is size of mac(on ethernet), 2 is link-layer type.... it can be 8 place mac... TO DO}hope will not be tested
        rel_forw.client_LL_lenght[0]=0;
        rel_forw.client_LL_type[1]=1;
        rel_forw.client_LL_type[0]=0;
        for(int i=0;i<7;i++){
          rel_forw.client_LL_value[i]=eptr->ether_shost[i];}
        rel_forw.int_id_opt[1]=OPTION_INTERFACE_ID;
        rel_forw.int_id_opt[0]=0;
        rel_forw.int_id_len[1]=3;
        rel_forw.int_id_len[0]=0;

// in iwhilendex_int is unique idenfifier for each interface(interfaces are numbered by index)
// we have to save that unique identifier into 3 bytes.... so we cast it into three decimal numbers that represents each value of byte, when we convert it back we get our unique identifier
        rel_forw.int_id_val[2]=index_int[index]%HEX_TO_DEC_CONST;
        rel_forw.int_id_val[1]=round((index_int[index]/HEX_TO_DEC_CONST)%HEX_TO_DEC_CONST);
        rel_forw.int_id_val[0]=round(((index_int[index]/HEX_TO_DEC_CONST)/HEX_TO_DEC_CONST)%HEX_TO_DEC_CONST);//should be okay? do not know if i dont have to round down

        //SENDING SOCKET WITH DATA
        int sockfd;
        int opt=1;
        struct sockaddr_in6 address;

        address.sin6_family=AF_INET6;
        address.sin6_port=htons(547);
        //address.sin6_addr=in6addr_any;
        if(inet_pton(AF_INET6,server,&(address.sin6_addr))!=1){
            error(1,13,"Error in function pton \n");//ALERT HERE ERRNO IS OUT OF DATE
        }

        if( (sockfd = socket(AF_INET6,SOCK_DGRAM,0))<0){
          error(1,14,"Error while creating socket\n");
        }

        if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,sizeof(opt))){
          error(1,15,"Error during setsockopt\n");
        }

        struct sockaddr_in6 sendAddr;
        sendAddr.sin6_family=AF_INET6;
        sendAddr.sin6_port=htons(547);
        sendAddr.sin6_addr=in6addr_any;
        if((bind(sockfd,(struct sockaddr *)&sendAddr,sizeof( sendAddr)))==-1){
          error(1,16,"Error during first bind\n");
        }
        //int len;
        //coppy everything what i have to array of u_char
        u_char *buffer=(u_char*)malloc(sizeof(relay_msg_f) + sizeof(u_char)*msg_size);
        if(buffer==NULL){
            error(1,21,"Malloc Error\n");
        }

        memcpy(buffer, &(rel_forw.msg_type),sizeof(u_char)); //0
        memcpy(buffer + 1, &(rel_forw.hop_count),sizeof(u_char)); //1
        memcpy(buffer + 2, &(rel_forw.link_addr),sizeof(u_char)*16);//2-17
        memcpy(buffer + 18, &(rel_forw.peer_addr),sizeof(u_char)*16);
        memcpy(buffer + 34, &(rel_forw.option_relay_msg),sizeof(u_char)*2);
        memcpy(buffer + 36, &(rel_forw.option_len),sizeof(u_char)*2);
        memcpy(buffer + 38, (relayed_dhcpv),sizeof(u_char)*msg_size);
        memcpy(buffer + 38+msg_size, &(rel_forw.client_LL_address),sizeof(u_char)*2);
        memcpy(buffer + 40+msg_size, &(rel_forw.client_LL_lenght),sizeof(u_char)*2);
        memcpy(buffer + 42+msg_size, &(rel_forw.client_LL_type),sizeof(u_char)*2);
        memcpy(buffer + 44+msg_size, &(rel_forw.client_LL_value),sizeof(u_char)*6);
        memcpy(buffer + 50+msg_size, &(rel_forw.int_id_opt),sizeof(u_char)*2);
        memcpy(buffer + 52+msg_size, &(rel_forw.int_id_len),sizeof(u_char)*2);
        memcpy(buffer + 54+msg_size, &(rel_forw.int_id_val),sizeof(u_char)*3);

        if(sendto(sockfd,buffer,(sizeof(u_char)*(57+msg_size)),0,(struct sockaddr *)&address,sizeof(address))<0){
          error(1,17,"Error during sendto\n");
        }

        u_char *bufferRec=malloc(sizeof(u_char)*1024);//Size of packet, big enough to fit the biggest possible received packet
        //int *clilen=malloc(sizeof(int));

        socklen_t *clilen=(socklen_t*)malloc(sizeof(socklen_t));
        if(clilen==NULL){
          error(1,21,"Malloc Error\n");
        }
        *clilen=sizeof(address);
        int recBytesN=recvfrom(sockfd,bufferRec,1024,0,(struct sockaddr *)&address,clilen);
        if(recBytesN<0){
          error(1,18,"Error during recvfrom\n");
        }

        relay_msg_r *reply;
        reply=(relay_msg_r*)bufferRec;
        if(reply->msg_type!=13 || reply->hop_count!=0){
          continue;
        }
        if(compare_addreses((reply->link_addr),(rel_forw.link_addr))!=0 || compare_addreses((reply->peer_addr),(rel_forw.peer_addr))!=0){
          error(0,19,"Different addreses this must not happen\n");//will not terminate
          continue;
        }
        int offset=LINK_ADDRESS_SIZE+PEER_ADDRESS_SIZE+MSG_TYPE_SIZE+HOP_COUNT_SIZE;//36+1+1+3
        int type=0;//type of the option
        int opt_size=0;//size of the option
        int msg_size=0;//size of the message
        u_char *relay_msg_reply;//message
        while(offset<recBytesN){
          msg_gen_form *part_rel_r;//message without options type and hop count
          part_rel_r=(msg_gen_form *)(bufferRec+offset);
          opt_size=(int)((part_rel_r->lenght[1])+((int)(part_rel_r->lenght[0]))*HEX_TO_DEC_CONST);
          type=(int)(part_rel_r->option[1])+((int)(part_rel_r->option[0]))*HEX_TO_DEC_CONST;

            //check if the interface is the same that was sent
          if(type==OPTION_INTERFACE_ID){
              u_char *int_id_val;
              int_id_val=(u_char*) (bufferRec+offset+OPTION_LEN_SIZE+OPTION_RELAY_MSG_SIZE);
              if(opt_size!=3){
                error(0,23,"Option id-interface is diferent size than send\n");
              }
              if((int_id_val[0]!=rel_forw.int_id_val[0]) || (int_id_val[1]!=rel_forw.int_id_val[1])||(int_id_val[2]!=rel_forw.int_id_val[2])){
                  error(0,20,"Different id-identifier option values this mmust not happen\n");
                  continue;
              }
          }
          if(type==OPTION_RELAY_MSG){
              relay_msg_reply=(u_char*)(bufferRec+offset+OPTION_LEN_SIZE+OPTION_RELAY_MSG_SIZE);
              msg_size=opt_size;
          }
            //set where to find new option
          offset=offset+OPTION_LEN_SIZE+OPTION_RELAY_MSG_SIZE+opt_size;
        }

        u_char *message=(u_char*)malloc(sizeof(u_char)*msg_size);
        message=memcpy(message,relay_msg_reply,(sizeof(u_char)*msg_size));

        //printf("\nsize:%d",msg_size);
        free(bufferRec);
        free(addr);
        free(clilen);
        free(buffer);

        if(close(sockfd)!=0){
          error(1,22,"close socket error\n");
        }

        //write prefix and mac
        if((dMark||sMark) && (dhcpv6->msq_type==REQUEST_MSG_TYPE)){

          offset=MSG_TYPE_SIZE+TRANSACTION_ID_SIZE;
          type=0;
          opt_size=0;
          while(offset<msg_size){
            msg_gen_form *part_rel_r;
            part_rel_r=(msg_gen_form *)(message+offset);

            opt_size=(int)((part_rel_r->lenght[1])+((int)(part_rel_r->lenght[0]))*HEX_TO_DEC_CONST);
            type=(int)(part_rel_r->option[1])+((int)(part_rel_r->option[0]))*HEX_TO_DEC_CONST;

            //behaveiour depends on typee of the assigned address, each type have own structures

            //structure for non-temporary adress
            if(type==IA_NA_OPT){
                u_char *int_id_val;//message inside the option
                msg_gen_form *IA_opt;//option inside the optinon
                int inner_opt_size=0;//inner option size

                //option inside the option map
                IA_opt=(msg_gen_form*)(message+offset+OPTION_LEN_SIZE+OPTION_RELAY_MSG_SIZE+IA_ID_SIZE+IA_ID_T_SIZE+IA_ID_T_SIZE);
                type=(int)(IA_opt->option[1])+((int)(IA_opt->option[0]))*HEX_TO_DEC_CONST;
                inner_opt_size=(int)((IA_opt->lenght[1])+((int)(IA_opt->lenght[0]))*HEX_TO_DEC_CONST);

                //offset for the inner option
                int inner_offset=offset+OPTION_LEN_SIZE+OPTION_RELAY_MSG_SIZE+IA_ID_SIZE+IA_ID_T_SIZE+IA_ID_T_SIZE;

                //going throught all the options
                while(inner_offset<offset+inner_opt_size+OPTION_LEN_SIZE+OPTION_RELAY_MSG_SIZE+IA_ID_SIZE+IA_ID_T_SIZE+IA_ID_T_SIZE){

                  //option that we are interested in
                  if(type==IA_PT_OPT){
                    int_id_val=(u_char*) (message+offset+OPTION_LEN_SIZE+OPTION_RELAY_MSG_SIZE+OPTION_LEN_SIZE+OPTION_RELAY_MSG_SIZE+IA_ID_SIZE+IA_ID_T_SIZE+IA_ID_T_SIZE);
                    struct sockaddr_in6 printAddr;

                    //pick up the ipv6 address from structure
                    for(i=0;i<16;i++)
                      printAddr.sin6_addr.s6_addr[i]=int_id_val[i];

                    //string for output
                    char *printCharAddr=malloc(sizeof(char)*129);
                    inet_ntop(AF_INET6,(struct sockaddr_in6*)&(printAddr.sin6_addr),printCharAddr,129);
                    if(dMark)
                      printf("%s,%s\n",printCharAddr,macAddr);
                    if(lMark){
                      setlogmask(LOG_UPTO(LOG_NOTICE));
                      openlog(NULL,LOG_CONS|LOG_PID|LOG_NDELAY,LOG_LOCAL0|LOG_LOCAL1 );
                      syslog(LOG_NOTICE,"%s,%s\n",printCharAddr,macAddr);
                      closelog();
                    }
                    free(printCharAddr);
                  }

                  //go to the next option
                  inner_offset=inner_offset+inner_opt_size;
                }

            }
            if(type==IA_TA_OPT){
              u_char *int_id_val;//message inside the option
              msg_gen_form *IA_opt;//option inside the optinon
              int inner_opt_size=0;//inner option size

              //option inside the option map
              IA_opt=(msg_gen_form*)(message+offset+OPTION_LEN_SIZE+OPTION_RELAY_MSG_SIZE+IA_ID_SIZE);
              type=(int)(IA_opt->option[1])+((int)(IA_opt->option[0]))*HEX_TO_DEC_CONST;
              inner_opt_size=(int)((IA_opt->lenght[1])+((int)(IA_opt->lenght[0]))*HEX_TO_DEC_CONST);

              //offset for the inner option
              int inner_offset=offset+OPTION_LEN_SIZE+OPTION_RELAY_MSG_SIZE+IA_ID_SIZE;

              //going throught all the options
              while(inner_offset<offset+inner_opt_size+OPTION_LEN_SIZE+OPTION_RELAY_MSG_SIZE+IA_ID_SIZE){

                //option that we are interested in
                if(type==IA_PT_OPT){
                  int_id_val=(u_char*) (message+offset+OPTION_LEN_SIZE+OPTION_RELAY_MSG_SIZE+OPTION_LEN_SIZE+OPTION_RELAY_MSG_SIZE+IA_ID_SIZE);
                  struct sockaddr_in6 printAddr;

                  //pick up the ipv6 address from structure
                  for(i=0;i<16;i++)
                    printAddr.sin6_addr.s6_addr[i]=int_id_val[i];

                  //string for output
                  char *printCharAddr=malloc(sizeof(char)*129);
                  inet_ntop(AF_INET6,(struct sockaddr_in6*)&(printAddr.sin6_addr),printCharAddr,129);
                  if(dMark)
                    printf("%s,%s\n",printCharAddr,macAddr);
                  if(lMark){
                    setlogmask(LOG_UPTO(LOG_NOTICE));
                    openlog(NULL,LOG_CONS|LOG_PID|LOG_NDELAY,LOG_LOCAL0|LOG_LOCAL1 );
                    syslog(LOG_NOTICE,"%s,%s\n",printCharAddr,macAddr);
                    closelog();
                  }
                  free(printCharAddr);
                }

                //go to the next option
                inner_offset=inner_offset+inner_opt_size;
              }

            }
            if(type==IA_PD_OPT){
              u_char *int_id_val;//message inside the option
              msg_gen_form *IA_opt;//option inside the optinon
              int inner_opt_size=0;//inner option size
              u_char* prefix;//prefix of the assigned address

              //option inside the option map
              IA_opt=(msg_gen_form*)(message+offset+OPTION_LEN_SIZE+OPTION_RELAY_MSG_SIZE+IA_ID_SIZE+IA_ID_T_SIZE+IA_ID_T_SIZE);
              type=(int)(IA_opt->option[1])+((int)(IA_opt->option[0]))*HEX_TO_DEC_CONST;
              inner_opt_size=(int)((IA_opt->lenght[1])+((int)(IA_opt->lenght[0]))*HEX_TO_DEC_CONST);

              //offset for the inner option
              int inner_offset=offset+OPTION_LEN_SIZE+OPTION_RELAY_MSG_SIZE+IA_ID_SIZE+IA_ID_T_SIZE+IA_ID_T_SIZE;

              //going throught all the options
              while(inner_offset<offset+inner_opt_size+OPTION_LEN_SIZE+OPTION_RELAY_MSG_SIZE+IA_ID_SIZE+IA_ID_T_SIZE+IA_ID_T_SIZE){

                  //option that we are interested in
                if(type==OPTION_IAPREFIX){
                  int_id_val=(u_char*) (message+offset+OPTION_LEN_SIZE+OPTION_RELAY_MSG_SIZE+OPTION_LEN_SIZE+OPTION_RELAY_MSG_SIZE+PREFERED_LIFETIME_SIZE+VALID_LIFETIME_SIZE+PREFIX_LEN_SIZE);
                  prefix= (u_char*) (message+offset+OPTION_LEN_SIZE+OPTION_RELAY_MSG_SIZE+OPTION_LEN_SIZE+OPTION_RELAY_MSG_SIZE+PREFERED_LIFETIME_SIZE+VALID_LIFETIME_SIZE);

                  //pick up the ipv6 address from structure
                  struct sockaddr_in6 printAddr;
                  for(i=0;i<16;i++)
                    printAddr.sin6_addr.s6_addr[i]=int_id_val[i];

                  //print out assigned address/prefix,macAddr
                  char *printCharAddr=malloc(sizeof(char)*129);
                  inet_ntop(AF_INET6,(struct sockaddr_in6*)&(printAddr.sin6_addr),printCharAddr,129);
                  if(dMark)
                    printf("%s,%d,%s\n",printCharAddr,(int)(*prefix),macAddr);

                  if(lMark){
                    setlogmask(LOG_UPTO(LOG_NOTICE));
                    openlog(NULL,LOG_CONS|LOG_PID|LOG_NDELAY,LOG_LOCAL0|LOG_LOCAL1 );
                    syslog(LOG_NOTICE,"%s,%d,%s\n",printCharAddr,(int)(*prefix),macAddr);
                    closelog();
                  }


                  free(printCharAddr);
                }
                //offset for the next option
                inner_offset=inner_offset+inner_opt_size;
              }
            }

              //set where to find new option
            offset=offset+OPTION_LEN_SIZE+OPTION_RELAY_MSG_SIZE+opt_size;
          }

        }
        //sending message from server to client
        sendSocketClient(rel_forw,message,msg_size,dev->name);
      }
    }
  }

  //CATCH signals and wait for the childs here
//  printf("this message should appear only once\n"); -> if print only once this there is only one proces that is not catching messages -> parent of

while(flag_exit){
  (void)i;//JUST TO SUPRESS ERROR MESSAGE
};
  // if(!catchHere){
  //   i--;
  //   for(;i>=0;i--){
  //     ;
  //   }
  // }

  return 0;
//there cannot be free because other processes are still running and main ends
}
