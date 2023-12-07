#include "utility.h"

void initOneLinkList(oneLinkList* lst) {
    lst->head = NULL;
    lst->size = 0;
}

void insert(oneLinkList* lst, char* data) {
    oneLinkNode *newNode = (oneLinkNode*) malloc(sizeof(oneLinkNode));
    newNode->data = data;
    newNode->next = NULL;

    oneLinkNode *current = lst->head;

    if (current == NULL) {
        lst->head = newNode;
        lst->size++;
        return;
    }
    else {
        while (current->next != NULL)
            current = current->next;
        current->next = newNode;
        lst->size++;
    }
}

char* pop_front(oneLinkList* lst) {
    if (lst->size == 0)
        return NULL;
    else {
        char* str = (char*) malloc(sizeof(char) * (lst->head->data->length));

        size_t i = 0;
        while(i < lst->head->data->length) {
            strcat(str, lst->head->data->label);
            i++;
        }

        lst->head = lst->head->next;
        free(lst->head);
        lst->size--;
        return str;
    }
}

const char* opcode_to_string(dns_opcode opcode) {
    switch (opcode)
    {
        case DNS_OP_QUERY:
            return "QUERY";

        case DNS_OP_IQUERY:
            return "IQUERY";

        case DNS_OP_STATUS:
            return "STATUS";
        default:
            return "RESERVED";
    }
}

uint16_t make_uint16(char msb, char lsb) {
    return (((uint16_t)msb) << 8) | (uint16_t)lsb;
}

/*
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
int read_header(int socket, dns_msg* msg) {
    const size_t HEADER_SIZE = 12;
    uint8_t buf[HEADER_SIZE];
    int bytes_num = recv(socket, &buf, HEADER_SIZE, 0);
    if (bytes_num == -1) return errno;
    if(bytes_num != HEADER_SIZE) abort();

    msg->header.id = make_uint16(buf[0], buf[1]);
    msg->header.type = (buf[2] & 0x80) >> 7; // 1000'0000
    msg->header.opcode = (buf[2] & 0x78) >> 3; // 0111'1000
    msg->header.flags = 0;
    msg->header.flags |= (buf[2] & 0x04) >> 2; // 0000'0100
    msg->header.flags |= (buf[2] & 0x02) >> 1; // 0000'0010
    msg->header.flags |= (buf[2] & 0x01); // 0000'0001
    msg->header.flags |= (buf[2] & 0x80) >> 7; // 1000'0000
    msg->header.zero = 0;
    msg->header.resp_code = (buf[3] & 0x0F); // 0000'1111

    msg->header.questions_count = make_uint16(buf[4], buf[5]);
    msg->header.answers_count = make_uint16(buf[6], buf[7]);
    msg->header.auth_records_count = make_uint16(buf[8], buf[9]);
    msg->header.additional_records_count = make_uint16(buf[10], buf[11]);

    return 1;
}

/*
*                                   1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
int read_question(int socket, dns_msg* msg) {
    uint16_t msg_size = 0;
    uint8_t msg_size_bytes[2];
    int bytes_num = recv(socket, &msg_size_bytes, sizeof(msg_size), 0);
    if (bytes_num == -1) return errno;
    assert(bytes_num == sizeof(msg_size));

    size_t label_size = 0;
    size_t lbl_sz_buff;

    for (size_t iter = 0; iter < msg->header.questions_count; ++iter) {
        label_size = recv(socket, &lbl_sz_buff, 1, 0);
        uint8_t buff[lbl_sz_buff];
        do {
            while (bytes_num != lbl_sz_buff) {
                bytes_num = recv(socket, buff, lbl_sz_buff, 0);
                insert(&msg->questions->labels, buff);
            }
        } while (label_size-- != 0);
        bytes_num = recv(socket, buff, 4, 0);
        insert(&msg->questions->labels, buff);
    }

    return 1;
}

dns_msg decode_msg(dns_msg* msg, char* buf) {
    dns_msg msg;
    msg.header.id = make_uint16(buf[0], buf[1]);
    msg.header.type = (buf[2] & 0x80) >> 7; // 1000'0000
    msg.header.opcode = (buf[2] & 0x78) >> 3; // 0111'1000
    msg.header.flags = 0;
    msg.header.flags |= (buf[2] & 0x04) >> 2; // 0000'0100
    msg.header.flags |= (buf[2] & 0x02) >> 1; // 0000'0010
    msg.header.flags |= (buf[2] & 0x01); // 0000'0001
    msg.header.flags |= (buf[2] & 0x80) >> 7; // 1000'0000
    msg.header.zero = 0;
    msg.header.resp_code = (buf[3] & 0x0F); // 0000'1111

    msg.header.questions_count = make_uint16(buf[4], buf[5]);
    msg.header.answers_count = make_uint16(buf[6], buf[7]);
    msg.header.auth_records_count = make_uint16(buf[8], buf[9]);
    msg.header.additional_records_count = make_uint16(buf[10], buf[11]);

    int label_size = 0;
    unsigned char lbl_sz_buff;

    for (size_t iter = 0; iter < msg.header.questions_count; ++iter) {
        do {
            label_size = recv(socket, &lbl_sz_buff, 1, 0);
            uint8_t buff[lbl_sz_buff];
            bytes_num = recv(socket, dns_msg_arr, lbl_sz_buff, 0);
            strcat(dns_msg_arr, buff);
        } while (label_size != 0);
    }

    return msg;
}

bool is_blacklisted(dns_msg msg, char* dns[], int size) {
    uint16_t msg_size = 0;
    char msg_size_bytes[2];
    int bytes_num = recv(socket, &msg_size_bytes, sizeof(msg_size), 0);
    if (bytes_num == -1) return errno;
    assert(bytes_num == sizeof(msg_size));

    const size_t HEADER_SIZE = 12;
    uint8_t header_bytes[HEADER_SIZE];
    bytes_num = recv(socket, header_bytes, HEADER_SIZE, 0);
    if (bytes_num == -1) return errno;
    if(bytes_num != HEADER_SIZE) {
        abort();
    }

    msg_header header;
    header.id = make_uint16(header_bytes[0], header_bytes[1]);
    header.type = (header_bytes[2] & 0x80) >> 7; // 1000'0000
    header.opcode = (header_bytes[2] & 0x78) >> 3; // 0111'1000
    header.flags = 0;
    header.flags |= (header_bytes[2] & 0x04) >> 2; // 0000'0100
    header.flags |= (header_bytes[2] & 0x02) >> 1; // 0000'0010
    header.flags |= (header_bytes[2] & 0x01); // 0000'0001
    header.flags |= (header_bytes[2] & 0x80) >> 7; // 1000'0000
    header.zero = 0;
    header.resp_code = (header_bytes[3] & 0x0F); // 0000'1111

    header.questions_count = make_uint16(header_bytes[4], header_bytes[5]);
    header.answers_count = make_uint16(header_bytes[6], header_bytes[7]);
    header.auth_records_count = make_uint16(header_bytes[8], header_bytes[9]);
    header.additional_records_count = make_uint16(header_bytes[10], header_bytes[11]);

    for (int i = 0; i < QUESTION_SIZE; ++i) {
        printf("%c", question_bytes[i]);
    }


    for (int i = 0; i < size; ++i) {
        if (*dns[i] == *question_bytes)
            return false;
    }
    return true;
}

char* encode_msg(const msg_header header) {
    const size_t DNS_MSG_SIZE = 512;
    char header_bytes[DNS_MSG_SIZE] = {0};

    header_bytes[2] |= (header.type << 7);
    header_bytes[2] |= (header.opcode << 3);
    header_bytes[2] &= (header.flags << 4);
    header_bytes[2] &= (header.flags << 2);
    header_bytes[2] &= (header.flags << 1);
    header_bytes[2] &= (header.flags);
    header_bytes[2] &= (header.flags << 7);

    header_bytes[3] |= header.resp_code;

    return header_bytes;
}

dns_msg* create_refuse_msg(id) {}

char* substr(char* src, int beg, int end) {
    int len = end - beg;
    char *dest = (char*)malloc(sizeof(char) * (len + 1));

    strncpy(dest, (src + beg), len);

    return dest;
}

bool starts_with(char* str, char* prefix) {
    for (int i = 0; i < strlen(prefix); ++i) {
        if (str[i] != prefix[i]) return false;
    }

    return true;
}

int posix_unwrap(int res, const char* msg) {
    if (res == -1) { perror(msg); abort(); }
    return res;
}