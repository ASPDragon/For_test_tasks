#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
// #include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

typedef struct domain_name_label;

// List structure and functions
typedef struct {
    struct domain_name_label* data;
    struct oneLinkNode *next;
} oneLinkNode;

typedef struct {
    oneLinkNode *head;
    int size;
} oneLinkList;

void initOneLinkList(oneLinkList*);
void insert(oneLinkList*, char*);
char* pop_front(oneLinkList*);

// Dns message structures and functions
typedef enum {
    MSG_QUERY = 0, MSG_RESPONSE = 1
} msg_type;

typedef enum {
    DNS_OP_QUERY = 0, DNS_OP_IQUERY = 1, DNS_OP_STATUS = 2
} dns_opcode;

const char* opcode_to_string(dns_opcode);

typedef enum {
    DNS_RESP_CODE_SUCCESS = 0,
    DNS_RESP_CODE_FMT_ERR = 1,
    DNS_RESP_CODE_SERVER_FAILURE = 2,
    DNS_RESP_CODE_NAME_ERR = 3,
    DNS_RESP_CODE_NOT_IMPLEMENTED = 4,
    DNS_RESP_CODE_REFUSED = 5,
} dns_response_code;

typedef enum {
    DNS_FLAG_AUTH_ANSWER = 0x1,
    DNS_FLAG_TRUNCATED = 0x2,
    DNS_FLAG_RECURSION_DESIRED = 0x4,
    DNS_FLAG_RECURSION_SUPPORTED = 0x8,
} dns_flags;

typedef struct {
    uint16_t id;

    msg_type type; // 1 bit
    dns_opcode opcode; // 4 bit
    dns_flags flags; // 4 bit
    uint8_t zero; // 3 bit
    dns_response_code resp_code; // 4 bit

    uint16_t questions_count;
    uint16_t answers_count;
    uint16_t auth_records_count;
    uint16_t additional_records_count;
} msg_header;

typedef struct domain_name_label {
    uint8_t length;
    char* label;
} domain_name_label;

typedef struct {
    oneLinkList labels;
    uint16_t type;
    uint16_t class;
} question_section;

typedef struct {
    char* name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    char* rdata;
} resource_record_section;

typedef struct {
    msg_header header;
    question_section* questions;
    resource_record_section* answers;
    resource_record_section* authorities;
    resource_record_section* additional;
} dns_msg;

uint16_t make_uint16(char, char);

int read_header(int, uint8_t*);
int read_msg(int, uint8_t*);
dns_msg decode_msg(char*);
bool is_blacklisted(dns_msg msg, char* dns[], int size);
char* encode_msg(const msg_header);
dns_msg* create_refuse_msg(id);

// Some utility functions
char* substr(char*, int, int);
bool starts_with(char*, char*);
int posix_unwrap(int, const char*);