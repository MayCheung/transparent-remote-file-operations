/**
 * server.c: Receives the rpc requests from clients and performs them locally.
 * Author: Kamal Balasubramanian Sharath
 * AndrewId: kamalanb
 */
#pragma pack(0)
#include <err.h>
#include <dlfcn.h>
#include <stdio.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include "packets.h"
#include "dirtree.h"
#include <errno.h>
#include <netinet/tcp.h>
#include <dirent.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MAXMSGLEN 100
#define ERROR -1
#define OPEN 1
#define CLOSE 2
#define WRITE 3
#define READ 4
#define LSEEK 5
#define UNLINK 6
#define STAT 7
#define GETDIRENTRIES 8
#define DIRTREENODE 9
#define FREEDIRTREE 10
#define CLOSE_CONNECTION -255
#define SUCCESS 1
#define FAILURE 0


void Open(int sessfd,void *buffer);
void Close(int sessfd,void *recvBuffer);
void Write(int sessfd,void *recvBuffer);
void Read(int sessfd,void *recvBuffer);
void Lseek(int sessfd,void *recvBuffer);
void Unlink(int sessfd,void *recvBuffer);
void Stat(int sessfd,void *recvBuffer);
void Getdirentries(int sessfd,void *recvBuffer);

void Getdirtree(int sessfd,void *recvBuffer);
void sendDepthFirstTraversal(struct dirtreenode * root,int sessfd);
void sigchld_handler(int sig);
/**
 * sigchld_handler(): Reaps all zombie children.
 */
void sigchld_handler(int sig)
{
	int pid= -1;//all processes
	while (waitpid(pid, 0, WNOHANG) > 0)
 	{

 	}
 	return;
}
/**
 * Send(): Sends 'total' number of bytes from sendBuffer to fd specified by
 * sockfd.
 */
int Send(int sockfd,void *sendBuffer,size_t total1,int option)
{
    size_t total = total1;
    int sent = send(sockfd,sendBuffer, total,option);
    if(sent<0)
    { 
        err(1,0);
    }
       	
    return SUCCESS;
}

/**
 * Recv(): Receives 'total' number of bytes on recvBuffer from fd specified by
 * sockfd.
 */

int Recv(int sockfd,void *recvBuffer,size_t total1,int option)
{
    
	void *tempPtr = recvBuffer;
    size_t received = 0;
    ssize_t total = total1;
 
    while(total>0)
    {

        received= recv(sockfd,tempPtr,total,0);
        if(received<0)
        { 
        	err(1,0);
     	}
       	total = total-received;
       	tempPtr = tempPtr+received;
    }
     
    return SUCCESS;

}
/**
 * main(): Listen for connections from clients. Fork a child for each 
 * new connection to handle further requests from that specific client.
 */
int main(int argc, char**argv) {
	
	char *serverport;
	unsigned short port;
	int sockfd, sessfd, rv;
	struct sockaddr_in srv, cli;
	socklen_t sa_size;
	int pid;
	
	// Get environment variable indicating the port of the server
	serverport = getenv("serverport15440");
	if (serverport) port = (unsigned short)atoi(serverport);
	else port=15232;
	
	// Create socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);	// TCP/IP socket
	if (sockfd<0) err(1, 0);			// in case of error
	
	// setup address structure to indicate server port
	memset(&srv, 0, sizeof(srv));			// clear it first
	srv.sin_family = AF_INET;			// IP family
	srv.sin_addr.s_addr = htonl(INADDR_ANY);	// don't care IP address
	srv.sin_port = htons(port);			// server port

	// bind to our port
	rv = bind(sockfd, (struct sockaddr*)&srv, sizeof(struct sockaddr));
	if (rv<0) err(1,0);
	
	// start listening for connections
	rv = listen(sockfd, 5);
	if (rv<0) err(1,0);

	//Disable Nagle Algorithm
	int temp = 1;
	int result = setsockopt(sockfd, IPPROTO_TCP,TCP_NODELAY,(char *) &temp, 
                        sizeof(int));  
 	if (result < 0)
 	err(1,0);

 	signal(SIGCHLD, sigchld_handler);
	
	// main server loop, handle clients one at a time, quit after 10 clients
	while(1) {
		
		// wait for next client, get session socket
		sa_size = sizeof(struct sockaddr_in);
		sessfd = accept(sockfd, (struct sockaddr *)&cli, &sa_size);
		if (sessfd<0) err(1,0);
	   	
	   	pid = fork();
	   	if(pid > 0)
	   	{ 
	   		//parent
	   		close(sessfd);
	   		continue;
		}
		else
		{
			//child
			close(sockfd);
		}
		

		int opcode = -1;	

		while(opcode != CLOSE_CONNECTION) 
		{  	

		
		    request_header_t reqHeader;  
	        
	        void *recvBuffer;

			Recv(sessfd,&reqHeader,sizeof(request_header_t),0);
		

	        if(reqHeader.opcode == CLOSE_CONNECTION)
	        {
	    
	        	close(sessfd);
	        	exit(SUCCESS);
	        }
	        
	        if(reqHeader.parameterLen!= 0)
	        recvBuffer = malloc(reqHeader.parameterLen );
	        Recv(sessfd,recvBuffer,reqHeader.parameterLen ,0);

	        switch(reqHeader.opcode)
	        {

	            case OPEN:
	                       	Open(sessfd,recvBuffer);
	                       	free(recvBuffer);
	                       	break;

	            case CLOSE:
	            		
	    					Close(sessfd,recvBuffer);
	    					free(recvBuffer);
	    					break;
				case WRITE:
	            			
	    					Write(sessfd,recvBuffer);
	    					free(recvBuffer);
	    					break;
	    		case READ:
	    					Read(sessfd,recvBuffer);
	    					free(recvBuffer);
	    					break;

	    		case LSEEK:
	    					Lseek(sessfd,recvBuffer);
	    					free(recvBuffer);
	    					break;
	    		case UNLINK:
	    					Unlink(sessfd,recvBuffer);
	    					free(recvBuffer);
	    					break;
	    		case STAT:
	    					Stat(sessfd,recvBuffer);
	    					free(recvBuffer);
	    					break;
	    		case GETDIRENTRIES:
	    					Getdirentries(sessfd,recvBuffer);
	    					free(recvBuffer);
	    					break;
	    		case DIRTREENODE:
	    					Getdirtree(sessfd,recvBuffer);
	    					free(recvBuffer);
	    					break;
			};

		}   
			
	}
	
	
	// close socket
	close(sockfd);

	return 0;
}


/**
 * Open: Wrapper over open. Unmarshalls parameters and marshalls
 * return values for transmission after function call.
 */
void Open(int sessfd,void *buffer)
{
    open_request_header_t *openRequest = (open_request_header_t *)buffer;
    char *filename = malloc(openRequest->pathLen);
    memcpy(filename,openRequest->data,openRequest->pathLen);
    
    int fd = open(filename,openRequest->flag,openRequest->mode);

    int replyPacketSize = sizeof(fd)+sizeof(errno);

    void *replyPacket = malloc(replyPacketSize);

    memcpy(replyPacket,&fd,sizeof(fd));
    memcpy(replyPacket+sizeof(fd),&errno,sizeof(errno));

    //send the response back
    Send(sessfd,replyPacket,replyPacketSize,0);
    free(replyPacket);
    free(filename);

}
/**
 * Close: Wrapper over close. Unmarshalls parameters and marshalls
 * return values for transmission after function call.
 */
void Close(int sessfd,void *recvBuffer)
{
	close_request_header_t *closeRequest = (close_request_header_t *)recvBuffer;
	int fd = closeRequest->fd;

	int retVal = close(fd);

	int replyPacketSize = sizeof(retVal)+sizeof(errno);

    void *replyPacket = malloc(replyPacketSize);

    memcpy(replyPacket,&retVal,sizeof(retVal));
    memcpy(replyPacket+sizeof(retVal),&errno,sizeof(errno));
    //send the response back
    Send(sessfd,replyPacket,replyPacketSize,0);
    free(replyPacket);

}	
/**
 * Write: Wrapper over write. Unmarshalls parameters and marshalls
 * return values for transmission after function call.
 */
void Write(int sessfd,void *recvBuffer)
{

	write_request_header_t *writeRequest = (write_request_header_t *)recvBuffer;


	ssize_t retVal = write(writeRequest->fd,(void *)writeRequest->data,writeRequest->count);


	int replyPacketSize = sizeof(retVal)+sizeof(errno);


    void *replyPacket = malloc(replyPacketSize);

    memcpy(replyPacket,&retVal,sizeof(retVal));
    memcpy(replyPacket+sizeof(retVal),&errno,sizeof(errno));

    //send the response back
    Send(sessfd,replyPacket,replyPacketSize,0);
    free(replyPacket);

}
/**
 * Read: Wrapper over read. Unmarshalls parameters and marshalls
 * return values for transmission after function call.
 */
void Read(int sessfd,void *recvBuffer)
{

	read_request_header_t *readRequest = (read_request_header_t *)recvBuffer;

	void *readBuffer = malloc(readRequest->count);
	ssize_t retCount = read(readRequest->fd,readBuffer,readRequest->count);

	int replyPacketSize = sizeof(retCount)+sizeof(errno);
    void *replyPacket = malloc(replyPacketSize);

    memcpy(replyPacket,&retCount,sizeof(retCount));
    memcpy(replyPacket+sizeof(retCount),&errno,sizeof(errno));
    Send(sessfd,replyPacket,replyPacketSize,0);

    //send the response back
    if(retCount > 0)
    {	
    	Send(sessfd,readBuffer,retCount,0);
    }
    
    free(replyPacket);
    free(readBuffer);

}
/**
 * Lseek(): Wrapper over unlink: Unmarshalls parameters and marshalls
 * return values for transmission. 
 */
void Lseek(int sessfd,void *recvBuffer)
{

	lseek_request_header_t *lseekRequest = (lseek_request_header_t *)recvBuffer;
	off_t retVal = lseek(lseekRequest->fd,lseekRequest->offset,lseekRequest->whence);

	int replyPacketSize = sizeof(retVal)+sizeof(errno);
    void *replyPacket = malloc(replyPacketSize);

    memcpy(replyPacket,&retVal,sizeof(retVal));
    memcpy(replyPacket+sizeof(retVal),&errno,sizeof(errno));
    Send(sessfd,replyPacket,replyPacketSize,0);

    free(replyPacket);

}
/**
 * Unlink(): Wrapper over unlink: Unmarshalls parameters and marshalls
 * return values for transmission. 
 */
void Unlink(int sessfd,void *recvBuffer)
{
	unlink_request_header_t *unlinkRequest = (unlink_request_header_t*) recvBuffer;

	char *filename = malloc(unlinkRequest->pathLen);
    memcpy(filename,unlinkRequest->data,unlinkRequest->pathLen);
    
	int retVal = unlink(filename);

	int replyPacketSize = sizeof(retVal)+sizeof(errno);
    void *replyPacket = malloc(replyPacketSize);

    memcpy(replyPacket,&retVal,sizeof(retVal));
    memcpy(replyPacket+sizeof(retVal),&errno,sizeof(errno));
    Send(sessfd,replyPacket,replyPacketSize,0);

    free(replyPacket);
    free(filename);

}
/**
 * Stat(): Wrapper over stat. Unmarshalls parameters
 * and marshalls return values for transmission.
 */
void Stat(int sessfd,void *recvBuffer)
{
	stat_request_header_t *statRequest = (stat_request_header_t*) recvBuffer;

	
	char *filename = malloc(statRequest->pathLen);
    memcpy(filename,statRequest->data,statRequest->pathLen);

    struct stat buf;

    int retVal = __xstat(statRequest->ver,filename,&buf);

	int replyPacketSize = sizeof(retVal)+sizeof(errno);
    void *replyPacket = malloc(replyPacketSize);

    memcpy(replyPacket,&retVal,sizeof(retVal));
    memcpy(replyPacket+sizeof(retVal),&errno,sizeof(errno));
    Send(sessfd,replyPacket,replyPacketSize,0);

	Send(sessfd,&buf,sizeof(buf),0);

	free(replyPacket);
    free(filename);
}
/**
 * Getdirentries(): Wrapper over getdirentries. Unmarshalls parameters
 * and marshalls return values for transmission.
 */
void Getdirentries(int sessfd,void *recvBuffer)
{
	gdentries_request_header_t *gdeRequest = (gdentries_request_header_t*) recvBuffer;

	

	char *buf = malloc(gdeRequest->nbytes);
	off_t* basep = malloc(sizeof(off_t));
	*basep = gdeRequest->valAtbasep;

	ssize_t retVal=getdirentries(gdeRequest->fd,buf,gdeRequest->nbytes ,basep );

	int replyPacketSize = sizeof(retVal)+sizeof(errno);
    void *replyPacket = malloc(replyPacketSize);

    memcpy(replyPacket,&retVal,sizeof(retVal));
    memcpy(replyPacket+sizeof(retVal),&errno,sizeof(errno));
    Send(sessfd,replyPacket,replyPacketSize,0);

    
	//send basep
	Send(sessfd,basep,sizeof(off_t),0);

	if(retVal != ERROR)
		Send(sessfd,buf,retVal,0);

	free(replyPacket);
	free(buf);
	free(basep);
}

/**
 * Getdirtree(): Wrapper over getdirtree. Unmarshalls parameters
 * and marshalls return values for transmission.
 */
void Getdirtree(int sessfd,void *recvBuffer)
{

	getdirtree_request_header_t *treeRequest 
				= (getdirtree_request_header_t*) recvBuffer;
	
	char *path = malloc(treeRequest->pathLen);
	strcpy(path,(char  *)treeRequest->data);

	struct dirtreenode* root = getdirtree(path);

	int outcome = FAILURE;

	if(root!=NULL)
	{
		outcome = SUCCESS;
		Send(sessfd,&outcome,sizeof(outcome),0);		
		sendDepthFirstTraversal(root,sessfd);
	}
	else
	{
		outcome = FAILURE;
		Send(sessfd,&outcome,sizeof(outcome),0);
		Send(sessfd,&errno,sizeof(errno),0);		
	}

	free(path);
	freedirtree(root);
		
}

/**
 * sendDepthFirstTraversal(): Sends the tree in a preorder traversal
 * fashion.
 */
void sendDepthFirstTraversal(struct dirtreenode * root,int sessfd)
{

	int nameLen = strlen(root->name)+1;
	char *nameBuffer = malloc(nameLen);
	strcpy(nameBuffer,root->name);

	//Send Name Followed by Length;
	Send(sessfd,&nameLen,sizeof(nameLen),0);

	//Send Name
	Send(sessfd,nameBuffer,nameLen,0);

	//send Number of Entires;
	Send(sessfd,&root->num_subdirs,sizeof(int),0);

	int childIndex = 0;

	for(childIndex=0;childIndex<root->num_subdirs;childIndex++)
	{
		sendDepthFirstTraversal(root->subdirs[childIndex],sessfd);
	}
	free(nameBuffer);
}
