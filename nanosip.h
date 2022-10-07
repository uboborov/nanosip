#ifndef _NANOSIP_H_
#define _NANOSIP_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef OS_LINUX
# define IP4_ADDR(addr, a,b,c,d) (addr) = htonl(((uint32_t)((a) & 0xff) << 24) | \
                               ((uint32_t)((b) & 0xff) << 16) | \
                               ((uint32_t)((c) & 0xff) << 8) | \
                                (uint32_t)((d) & 0xff))
#endif

#define IS_CODE_IN_CLASS(status_code, code_class)   (status_code/100 == code_class/100)
#define DEF_SIP_PORT 5060
#define ip_to_str(str, ip) sprintf(str, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])

#define SIP_DOMAIN_MAXLENGTH   33
#define SIP_NAME_MAXLENGHT     64
#define SIP_UASTRING_MAXLENGHT 32
#define SIP_PASS_MAXLENGHT     10
#define SIP_EXPTIME_MAXLENGHT  10
#define SIP_BRANCH_MAXLENGHT   64
#define SIP_FROM_TAG_MAXLENGHT 64
#define SIP_TO_TAG_MAXLENGHT   64
#define SIP_CALLID_MAXLENGHT   64
#define SIP_NONCE_MAXLENGHT    8
#define SIP_REALM_MAXLENGHT    32
#define SIP_TO_FROM_VIA_MAXLENGHT     64

enum {
    SIP_METHOD_NONE = 0,
    SIP_METHOD_REGISTER,
    SIP_METHOD_INVITE,
    SIP_METHOD_INFO,
    SIP_METHOD_BYE,
    SIP_METHOD_CANCEL,
    SIP_METHOD_ACK,
    SIP_METHOD_MESSAGE,
    SIP_METHOD_UPDATE
};

enum {
    SIP_DLG_INIT = 0,
    SIP_DLG_REG_S1,
    SIP_DLG_REG_S2,
    SIP_DLG_REG_S3,
    SIP_DLG_REISTERED,
    SIP_DLG_CALLING,
    SIP_DLG_CALLING_S1,
    SIP_DLG_CALLING_S2,
    SIP_DLG_CALLING_S3,
    SIP_DLG_CONFIRMED,
    SIP_DLG_DISCONNECTED,
    SIP_DLG_IDLE,
    SIP_DLG_CLOSE,
    SIP_DLG_DONE,

    SIP_DLG_NST
};

enum {
    CALL_STATE_NONE = 0,
    CALL_STATE_CALLING,
    CALL_STATE_CONNECTING,
    CALL_STATE_TRYING,
    CALL_STATE_EARLY,
    CALL_STATE_CONFIRMED,
    CALL_STATE_DISCONNECTING,
    CALL_STATE_DISCONNECTED,
};

enum {
    SIP_DLG_MSG_NONE = 0,
    SIP_DLG_MSG_REG,
    SIP_DLG_MSG_CALL,
    SIP_DLG_MSG_HANGUP,
    SIP_DLG_MSG_EXIT
};

typedef struct sip_re {
    uint32_t cseq;
    uint32_t code;
    uint32_t request;
    uint32_t rem_rtp_port;
    char method[SIP_NAME_MAXLENGHT + 1];
    char uri[SIP_TO_FROM_VIA_MAXLENGHT + 1];
    char via[SIP_TO_FROM_VIA_MAXLENGHT + 1];
    char branch[SIP_BRANCH_MAXLENGHT + 1];
    char from[SIP_TO_FROM_VIA_MAXLENGHT + 1];
    char from_tag[SIP_FROM_TAG_MAXLENGHT + 1];
    char to[SIP_TO_FROM_VIA_MAXLENGHT + 1]; 
    char to_tag[SIP_TO_TAG_MAXLENGHT + 1];
    char contact[SIP_TO_FROM_VIA_MAXLENGHT + 1];
    char callid[SIP_CALLID_MAXLENGHT + 1];
    char auth[SIP_TO_FROM_VIA_MAXLENGHT + 1];
} re_t; 

typedef struct {
    uint8_t  ip[4];
    uint16_t port;
    uint32_t err;
} ep_t;


typedef struct {
    uint32_t cseq;
    re_t     req;
    re_t     res;
    char nonce[SIP_NONCE_MAXLENGHT + 1];
    char realm[SIP_REALM_MAXLENGHT + 1];
    uint32_t registered;
    uint32_t call_state;
    // server
    uint8_t servip[4];
    uint8_t localip[4];

    uint8_t servip_str[15];
    uint8_t localip_str[15];

    ep_t   ep_sip;
    ep_t   ep_rtp;

    char locname[SIP_NAME_MAXLENGHT];
    char uastring[SIP_UASTRING_MAXLENGHT];
    char remname[SIP_TO_FROM_VIA_MAXLENGHT + 1];
    char pass[SIP_PASS_MAXLENGHT];
    char domain[SIP_DOMAIN_MAXLENGTH];
    char direct_uri[SIP_TO_FROM_VIA_MAXLENGHT + 1];

    uint32_t exp_time;
    uint32_t serv_sip_port;
    uint32_t local_sip_port;
    uint32_t local_rtp_port;
    uint32_t rem_rtp_port;

    uint32_t call_media_active;
    int sockfd;
    //
    uint32_t last_code;
    uint32_t last_method;
    uint32_t reinvite;
    uint32_t state;
    uint32_t prev_state;
    volatile uint32_t msg;

    void (*dlg_calling_cb)(int);
    void (*dlg_connected_cb)(int);
    void (*dlg_finished_cb)(int);
} sipdialog_t;

void nanosip_gen_rndstr(char *str, uint8_t len);
int nanosip_parse_pkt(char *str, re_t *req);
int nanosip_get_response_code(re_t *res);
void nanosip_copy_request(char *pb, char *met, re_t *req, re_t *res);
void nanosip_invite_sesponse(char *pb, re_t *req);
int nanosip_get_request_method(char *method);
int nanosip_get_aut_param(re_t *req, char *realm, char *nonce);
void nanosip_dialog_request(sipdialog_t *dlg, char *pb, char *met, 
                            int auth, char *content);
void nanosip_dialog_response(sipdialog_t *dlg, char *pb, int code, 
                             char *reason, char *content);
void nanosip_gen_default_sdp(sipdialog_t *dlg, char *pb);

void nanosip_print_re(re_t *req);
int nanosip_create_socket(sipdialog_t *dlg);
int nanosip_validate_sip_uri(char *url, char *pname, char *pip, int *pport);
int nanosip_init_buffers();
#endif
