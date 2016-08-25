/**
 * packets.h: Contains structure declarations for packets.
 */
typedef struct 
{ 
	
	size_t parameterLen; // Dictates how many bytes we need to request from recv()
	int opcode; // Operation: open/close/read/write
	int filler;
	unsigned char data[0]; // This points to the next byte after this struct
} request_header_t;

typedef struct
{ 
	int flag;
	mode_t mode;
	int pathLen;
	unsigned char data[0];
} open_request_header_t;

typedef struct
{ 
 	int fd;
} close_request_header_t;


typedef struct 
{
	int count;
	int fd;
	unsigned char data[0];
	
}write_request_header_t;

typedef struct 
{
	
	size_t count;//size_t?
	int fd;
	int filler;
	unsigned char data[0];
}read_request_header_t;

typedef struct 
{
	int fd;
	int whence;
	off_t offset;
} lseek_request_header_t;


typedef struct 
{
	int pathLen;
	unsigned char data[0];
}unlink_request_header_t;

typedef struct 
{
	int ver;
	int pathLen;
	unsigned char data[0];
}stat_request_header_t;


typedef struct 
{
	
	size_t nbytes;//size_t?
	off_t valAtbasep;
	int fd;
	int filler;

}gdentries_request_header_t;


typedef struct 
{
	int pathLen;
	unsigned char data[0];
}getdirtree_request_header_t;


typedef struct 
{
	size_t parameterLen;
	int opcode;
	int filler;
}close_connection_header_t;
