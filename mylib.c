/**
 * mylib.c : 
 * Author: Kamal Balasubramanian Sharath
 * This library makes remote procedure calls for file operations
 * on a server connected via TCP.
 */

#define _GNU_SOURCE
#pragma pack(0)
#include <dlfcn.h>
#include <stdio.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include "dirtree.h"
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <string.h>
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include "packets.h"
#include <errno.h>
#include <stdbool.h>

#define MAXMSGLEN 100
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
#define ERROR -1
#define CLOSE_CONNECTION -255
#define SUCCESS 1
#define THRESHOLD 10000

//Global file descriptor client connections
static int gClientfd = -1;


//The following line declares a function pointer with the same prototype as the open function.  
void openComm();
int (*orig_open)(const char *pathname, int flags, ...);
int (*orig_close)(int fd);
ssize_t (*orig_read)(int fd,void *buf,size_t count);
ssize_t (*orig_write)(int fd, const void *buf, size_t count);

off_t (*orig_lseek)(int fd, off_t offset, int whence);
int (*orig_unlink)(const char *pathname);

int (*orig_stat)(int ver,const char *path, struct stat *buf);
ssize_t (*orig_getdirentries)(int fd, char *buf, size_t nbytes , off_t *basep);
struct dirtreenode* (*orig_getdirtree)( const char *path );
void (*orig_freedirtree)( struct dirtreenode* dt );
struct dirtreenode* receiveDepthFirstTraversal(struct dirtreenode * root);
void depthFirstFree(struct dirtreenode *dt);


/**
 * isRPC(): Determines if the fd specified is for a local or remote file 
 * operation by comparing with a threshold.
 */
bool isRPC(int fd)
{
	if(fd < THRESHOLD)
	{
		return false;
	}
	else
	{
		return true;
	}
}

/**
 * openComm(): Opens a TCP connection with the rpc server.
 */
void openComm()
{

	char *serverip;
	char *serverport;
	unsigned short port;
    int rv;
	struct sockaddr_in srv;
	
	// Get environment variable indicating the ip address of the server
	serverip = getenv("server15440");
	if (serverip) 
	{
		fprintf(stderr,"Got environment variable server15440: %s\n", serverip);
	}
	else 
	{
		fprintf(stderr,"Environment variable server15440 not found.  Using 127.0.0.1\n");
		serverip = "127.0.0.1";
	}
	
	// Get environment variable indicating the port of the server
	serverport = getenv("serverport15440");
	if (serverport) 
	{
		fprintf(stderr, "Got environment variable serverport15440: %s\n", serverport);
	}
	else
	{
		fprintf(stderr, "Environment variable serverport15440 not found.  Using 15440\n");
		serverport = "15232";
	}
	port = (unsigned short)atoi(serverport);
	
	// Create socket
	gClientfd = socket(AF_INET, SOCK_STREAM, 0);	// TCP/IP socket
	if (gClientfd<0) err(1, 0);			// in case of error
	
	// setup address structure to point to server
	memset(&srv, 0, sizeof(srv));			// clear it first
	srv.sin_family = AF_INET;			// IP family
	srv.sin_addr.s_addr = inet_addr(serverip);	// IP address of server
	srv.sin_port = htons(port);			// server port

	// actually connect to the server
	rv = connect(gClientfd, (struct sockaddr*)&srv, sizeof(struct sockaddr));
	if (rv<0) err(1,0);


	//Disable Nable Algorithm
	int temp = 1;
	int result = setsockopt(gClientfd, IPPROTO_TCP,TCP_NODELAY,(char *) &temp, 
                        sizeof(int));  
 	if (result < 0)
	 	err(1,0);

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
 * open(): RPC open. Serializes parameters and sends to server for procedure 
 * call.
 *
 * Message Format to server:
 * |OPCODE| PARAMETERLENGTH| PATHLENGTH| MODE|FLAGS|PATH
 *
 * Reply message from server:
 * |FD|ERRNO
 * 
 */
int open(const char *pathname, int flags, ...) {
	mode_t m=0;
    
	if (flags & O_CREAT)
    {
		va_list a;
		va_start(a, flags);
		m = va_arg(a, mode_t);
		va_end(a);
	}

    //Determine Pathname length.
    int pathLen = strlen(pathname)+1; // Takes care of null char at end

    //parameter Length
    size_t parameterLen = sizeof(pathLen) + pathLen + sizeof(flags) + sizeof(m);

    //Total Length
    size_t totalLen = sizeof(request_header_t) + parameterLen;

    
    //Pack the data
    void *sendBuffer = malloc(totalLen);

    request_header_t* requestHeader = (request_header_t*) sendBuffer;
    requestHeader->opcode = OPEN;
    requestHeader->parameterLen = parameterLen ;
    requestHeader->filler=0;

    open_request_header_t *openRequest = (open_request_header_t *) requestHeader->data;
    openRequest->flag = flags;
    openRequest->mode = m;
    openRequest->pathLen = pathLen;//Takes care of null too

    char *filePath = (char *)openRequest->data;
    strcpy(filePath,pathname);
    
    //Send Parameters
    Send(gClientfd,sendBuffer,totalLen,0);
    
    //Reception
    int recSize = sizeof(int)+ sizeof(errno);
    void *recvBuffer = malloc(recSize);
    int rpcSockfd;
    

    Recv(gClientfd,recvBuffer,recSize,0);

    memcpy(&rpcSockfd,recvBuffer,sizeof(rpcSockfd));
    memcpy(&errno,recvBuffer+sizeof(rpcSockfd),sizeof(errno));

    if(rpcSockfd!=ERROR)
    	rpcSockfd = rpcSockfd+THRESHOLD;
	

    free(sendBuffer);    
    free(recvBuffer);
   
	return rpcSockfd;
}

/**
 * close(): RPC close. Serializes parameters and sends to server for procedure 
 * call.
 *
 * Message Format to server:
 * |OPCODE| PARAMETERLENGTH| PATHLENGTH| MODE|FLAGS|PATH
 *
 * Reply message from server:
 * |FD|ERRNO
 * 
 */
int close(int fd)
{
    
    if(isRPC(fd)==false)
    {
    	return orig_close(fd);
    }
    else
    {
    	fd = fd - THRESHOLD;
    }

    int sendLen = sizeof(request_header_t)+ sizeof(close_request_header_t);
    void *sendBuffer = malloc(sendLen);

    request_header_t* requestHeader = (request_header_t*) sendBuffer;
    requestHeader->opcode = CLOSE;
    requestHeader->parameterLen = sizeof(fd);
    requestHeader->filler=0;

    close_request_header_t *closeRequest = (close_request_header_t *)requestHeader->data;

    closeRequest->fd = fd;

    int sent = Send(gClientfd,sendBuffer,sendLen,0);
    if(sent<0) 
    {
    	err(1,0);
    }

    //Reception
    int recSize = sizeof(int)+sizeof(errno);
    int returnVal;
    void *recvBuffer = malloc(recSize);
    Recv(gClientfd,recvBuffer,recSize, 0);
    memcpy(&returnVal,recvBuffer,sizeof(returnVal));
    memcpy(&errno,recvBuffer+sizeof(returnVal),sizeof(errno));

    free(sendBuffer);    
    free(recvBuffer);
    return returnVal;
}

/**
 * write(): RPC write. Serializes parameters and sends to server for procedure 
 * call.
 *
 * Message Format to server:
 * |OPCODE| PARAMETERLENGTH| FD| COUNT
 *
 * Reply message from server:
 * |COUNT|ERRNO
 * 
 */
ssize_t write(int fd, const void *buf, size_t count)
{

	if(isRPC(fd)==false)
	{
    	return orig_write(fd,buf,count);
	}
    else
    {
    	fd = fd - THRESHOLD;
    }

    size_t paramLen = sizeof(write_request_header_t)+count;
    
    // opcode / paramlen/ fd/ count/ count Bytes
    size_t totalLen = sizeof(request_header_t) + paramLen;
    void* sendBuffer = malloc(totalLen);

    //Opcode + paramLen
    request_header_t* requestHeader = (request_header_t*) sendBuffer;
    requestHeader->opcode = WRITE;
    requestHeader->parameterLen = paramLen;
  	requestHeader->filler=0;  

    //Parameters
    write_request_header_t *writeRequest = (write_request_header_t *)requestHeader->data;

    //fd , count
    writeRequest->fd = fd;
    writeRequest->count = count;

    char *temp = (char *)writeRequest->data;
    memcpy(temp,buf,count);

    Send(gClientfd,sendBuffer,totalLen,0);

    //Reception
    ssize_t recSize = sizeof(ssize_t)+sizeof(errno);
    void *recvBuffer = malloc(recSize);
    ssize_t returnVal;

    Recv(gClientfd,recvBuffer,recSize, 0);


    memcpy(&returnVal,recvBuffer,sizeof(returnVal));
    memcpy(&errno,recvBuffer+sizeof(returnVal),sizeof(errno));


    free(sendBuffer);    
    free(recvBuffer);

    return returnVal;
}

/**
 * read(): RPC read. Serializes parameters and sends to server for procedure 
 * call.
 *
 * Message Format to server:
 * |OPCODE| PARAMETERLENGTH| FD| COUNT
 *
 * Reply message(s) from server:
 * |COUNT|ERRNO|
 * | READ CONTENT | 
 */
ssize_t read(int fd, void *buf, size_t count)
{

	
	if(isRPC(fd)==false)
	{
    	return orig_read(fd,buf,count);
	}
    else
    {
    	fd = fd - THRESHOLD;
    }

    
    size_t paramLen = sizeof(read_request_header_t);

    int opcode = READ;

    size_t totalLen = sizeof(request_header_t)+
    				paramLen;

    void *sendBuffer = malloc(totalLen);
    request_header_t* requestHeader = (request_header_t*) sendBuffer;
    requestHeader->opcode = opcode;
    requestHeader->parameterLen = paramLen;
    requestHeader->filler=0;
    read_request_header_t *readRequest = (read_request_header_t*) requestHeader->data;


    //fd,count
    readRequest->fd = fd;
    readRequest->count = count;
    readRequest->filler = 0;

    //sent;
    Send(gClientfd,sendBuffer,totalLen,0);

	//Received in the order of count and errno
    ssize_t returnCount;

    Recv(gClientfd,&returnCount,sizeof(returnCount), 0);
    Recv(gClientfd,&errno,sizeof(errno), 0);
    if(returnCount != ERROR)
    {
    
    	Recv(gClientfd,buf,returnCount,0);
    }
	    
	
    free(sendBuffer);
    return returnCount;
}

/**
 * lseek(): RPC lseek. Serializes parameters and sends to server for procedure 
 * call.
 *
 * Message Format to server:
 * |OPCODE| PARAMETERLENGTH| FD| WHENCE | OFFSET
 *
 * Reply message(s) from server:
 * |RETURN VAL |ERRNO| 
 */
off_t lseek(int fd, off_t offset, int whence)
{
    
    if(isRPC(fd)==false)
    {
    	return orig_lseek(fd,offset,whence);
    }
    else
    {
    	fd = fd - THRESHOLD;
    }

    size_t paramLen = sizeof(lseek_request_header_t);
   	int opcode = LSEEK;
   	size_t totalLen = sizeof(request_header_t)+
    				paramLen;

    void *sendBuffer = malloc(totalLen);
    request_header_t* requestHeader = (request_header_t*) sendBuffer;
    requestHeader->opcode = opcode;
    requestHeader->parameterLen = paramLen;
    requestHeader->filler=0;
    lseek_request_header_t *lseekRequest =  (lseek_request_header_t*) requestHeader->data;

    lseekRequest->fd = fd;
    lseekRequest->offset = offset;
    lseekRequest->whence=whence;

	//sent;
    Send(gClientfd,sendBuffer,totalLen,0);

    /**
    *	Reception code
    */
	//Received in the order of count and errno
    off_t returnVal;
    Recv(gClientfd,&returnVal,sizeof(returnVal), 0);
    Recv(gClientfd,&errno,sizeof(errno), 0);
    free(sendBuffer);
    return returnVal;

}
/**
 * unlink(): RPC unlink. Serializes parameters and sends to server for procedure 
 * call.
 *
 * Message Format to server:
 * |OPCODE| PARAMETERLENGTH| PATHNAMELEN| PATHNAME
 *
 * Reply message(s) from server:
 * |RETURN VAL |ERRNO| 
 */
int unlink(const char *pathname)
{

	
    int opcode = UNLINK;
    int pathLen = strlen(pathname)+1;//takes care of null
	
    size_t paramLen = sizeof(pathLen)+pathLen;
    
    size_t totalLen = sizeof(request_header_t)+paramLen;
    
    void *sendBuffer = malloc(totalLen);
    request_header_t* requestHeader = (request_header_t*) sendBuffer;
    requestHeader->opcode = opcode;
    requestHeader->parameterLen = paramLen;
    requestHeader->filler=0;
    unlink_request_header_t *unlinkRequest = (unlink_request_header_t*) requestHeader->data;

    unlinkRequest->pathLen = pathLen;

    char *filePath = (char *)unlinkRequest->data;
    strcpy(filePath,pathname);
    
    Send(gClientfd,sendBuffer,totalLen,0);
	
	int returnVal;

    Recv(gClientfd,&returnVal,sizeof(returnVal), 0);
    
    Recv(gClientfd,&errno,sizeof(errno), 0);
    
    free(sendBuffer);

    return returnVal;

}
/**
 * _xstat(): RPC Unlink(): Serializzes parameters and sends to server for
 * 	procedure call.
 *  
 * Message Format to server:
 * |OPCODE| PARAMETERLENGTH| VER| PATHNAMELEN| PATHNAME
 *
 * Reply message(s) from server:
 * |RETURN VAL |ERRNO| 
 * |BUF|
 */

int __xstat(int ver,const char *path, struct stat *buf)
{
	int opcode = STAT;

	int pathLen = strlen(path) +1;//takes care of null

	size_t paramLen = sizeof(ver)+ sizeof(pathLen)+pathLen;

	size_t totalLen = sizeof(request_header_t)+paramLen;

    void *sendBuffer = malloc(totalLen);
    request_header_t* requestHeader = (request_header_t*) sendBuffer;
    requestHeader->opcode = opcode;
    requestHeader->parameterLen = paramLen;
    requestHeader->filler=0;
    stat_request_header_t *statRequest = (stat_request_header_t*) requestHeader->data;

    statRequest->ver = ver;
    statRequest->pathLen = pathLen;

    char *filepath = (char *)statRequest->data;
    strcpy(filepath,path);

	Send(gClientfd,sendBuffer,totalLen,0);

	//Reception
	//Received in the order of return Val and errno
    int returnVal;

    Recv(gClientfd,&returnVal,sizeof(returnVal), 0);
    
    Recv(gClientfd,&errno,sizeof(errno), 0);
    
    Recv(gClientfd,buf,sizeof(struct stat),0);

    free(sendBuffer);

    return returnVal;

}
/**
 * getdirentries(): RPC getdirentries(): Serializes parameters and sends to server for
 * 	procedure call.
 *  
 * Message Format to server:
 * |OPCODE| PARAMETERLENGTH| FD| NBYTES | BASEP|
 *
 * Reply message(s) from server:
 * |RETURN VAL |ERRNO| 
 * |BUF|
 */
ssize_t getdirentries(int fd, char *buf, size_t nbytes , off_t *basep)
{


	if(isRPC(fd)==false)
	{
    	return orig_getdirentries(fd,buf,nbytes,basep);
	}
    else
    {
    	fd = fd - THRESHOLD;
    }

    //send a message to the server wth the fucntion name
    fprintf(stderr,"mylib getdire called!\n");


    int opcode = GETDIRENTRIES;

    size_t paramLen = sizeof(gdentries_request_header_t);
    
    size_t totalLen = sizeof(request_header_t)+paramLen;

    void *sendBuffer = malloc(totalLen);

    request_header_t* requestHeader = (request_header_t*) sendBuffer;
    requestHeader->opcode = opcode;
    requestHeader->parameterLen = paramLen;
    requestHeader->filler=0;
    gdentries_request_header_t *gdentriesRequest = (gdentries_request_header_t*) requestHeader->data;

    int filler=0;
    gdentriesRequest->fd = fd;
    gdentriesRequest->nbytes=nbytes;
    gdentriesRequest->valAtbasep= *basep;
    gdentriesRequest->filler = filler;// for alignment purposes.


    Send(gClientfd,sendBuffer,totalLen,0);

    //Receive;
	//Received in the order of return Val and errno
    ssize_t returnVal;

    Recv(gClientfd,&returnVal,sizeof(returnVal), 0);

    Recv(gClientfd,&errno,sizeof(errno), 0);
    
    //copy basep
	Recv(gClientfd,basep,sizeof(off_t), 0);


	if(returnVal != ERROR)
	{
		Recv(gClientfd,buf,returnVal,0);
	}

	free(sendBuffer);
	
    return returnVal;

}

/**
 * getdirtree(): Gets the tree of directories, rooted at the
 * directory pointed to by path.
 */
struct dirtreenode* getdirtree( const char *path )
{

    
    int opcode = DIRTREENODE;
    int pathLen = strlen(path)+1;//take care of null

    size_t paramLen = sizeof(pathLen) + pathLen;


  	size_t totalLen = sizeof(request_header_t)
  					+paramLen;  

  	void *sendBuffer = malloc(totalLen);

    request_header_t* requestHeader = (request_header_t*) sendBuffer;
    requestHeader->opcode = opcode;
    requestHeader->parameterLen = paramLen;

    getdirtree_request_header_t* treeRequest = (getdirtree_request_header_t*) requestHeader->data;

    treeRequest->pathLen = pathLen;

    char *pathName = (char *) treeRequest->data;
    strcpy(pathName,path);

    Send(gClientfd,sendBuffer,totalLen,0);


    //Reception Code.
    int returnVal;

    Recv(gClientfd,&returnVal,sizeof(returnVal), 0);


    struct dirtreenode* root = NULL;
    if(returnVal == SUCCESS)
    {
    	root=receiveDepthFirstTraversal(root);
    }
    else
    {
    	Recv(gClientfd,&errno,sizeof(errno), 0);
    }


    free(sendBuffer);
    return root;

}

/**
 * Receives the directory tree and constructs it in a top down fashion.
 */
struct dirtreenode* receiveDepthFirstTraversal(struct dirtreenode * root)
{

	root = malloc(sizeof(struct dirtreenode));


	// Initialize;
	root->num_subdirs=0;
	root->name = NULL;
	root->subdirs=NULL;
	int nameLen = 0;

	//Receive Length, followed by length;
	Recv(gClientfd,&nameLen,sizeof(nameLen),0);

	//Receive Name into Buffer
	root->name = malloc(nameLen);
	Recv(gClientfd,root->name,nameLen,0);
	

	//send Number of Entires;
	Recv(gClientfd,&root->num_subdirs,sizeof(int),0);

	root->subdirs = malloc(root->num_subdirs * sizeof(struct dirtreenode*));

	int childIndex = 0;

	for(childIndex=0;childIndex<root->num_subdirs;childIndex++)
	{
		root->subdirs[childIndex]=receiveDepthFirstTraversal(root->subdirs[childIndex]);
	}

	return root;

}

/**
 * freedirtree(): Frees the tree rooted at dt.
 */
void freedirtree( struct dirtreenode* dt )
{

    depthFirstFree(dt);
    return;
}

/**
 * depthFirstFree(): Recursively frees the entire tree by post order
 * traversal.
 */
void depthFirstFree(struct dirtreenode*dt)
{
	int childIndex=0;
	for(childIndex=0;childIndex<dt->num_subdirs;childIndex++)
	{
		depthFirstFree(dt->subdirs[childIndex]);
	}	
	free(dt->subdirs);
	free(dt->name);
	free(dt);
}


/**
 * _init():This function is automatically called when program is started
 */
void _init(void) {

    //Open Communications with server
    openComm();

    // set function pointer orig_open to point to the original open function
	orig_open = dlsym(RTLD_NEXT, "open");
    orig_close = dlsym(RTLD_NEXT,"close");
    orig_read = dlsym(RTLD_NEXT,"read");
    orig_write = dlsym(RTLD_NEXT,"write");

    orig_lseek = dlsym(RTLD_NEXT,"lseek");
    orig_unlink = dlsym(RTLD_NEXT,"unlink");

    orig_stat = dlsym(RTLD_NEXT,"__xstat");

    orig_getdirentries = dlsym(RTLD_NEXT,"getdirentries");
    
    orig_getdirtree = dlsym(RTLD_NEXT,"getdirtree");

    orig_freedirtree = dlsym(RTLD_NEXT,"freedirtree");

}

/**
 * _fini(): Close the connection with the server. Marking end of rpc library
 * calls from this client.
 */
void _fini(void)
{

    close_connection_header_t closeConn;
    closeConn.opcode = CLOSE_CONNECTION;
    closeConn.parameterLen = 0;
    closeConn.filler = 0;
  
    send(gClientfd,&closeConn, sizeof(closeConn),0);    
    orig_close(gClientfd);
}

