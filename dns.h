struct DNS_HEADER
{
    unsigned short id;
 
    unsigned char rd :1;
    unsigned char tc :1;
    unsigned char aa :1;
    unsigned char opcode :4;
    unsigned char qr :1; 
 
    unsigned char rcode :4;
    unsigned char cd :1; 
    unsigned char ad :1; 
    unsigned char z :1; 
    unsigned char ra :1;
 
    unsigned short q_count;
    unsigned short ans_count;
    unsigned short auth_count;
    unsigned short add_count; 
}__attribute__((packed));

struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
}__attribute__((packed));

struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
}__attribute__((packed));
