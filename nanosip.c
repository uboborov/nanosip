#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifndef OS_LINUX
#   include <lwip/sys.h>
#   include <lwip/api.h>
#   include <lwip/stats.h>
#   include <lwip/sockets.h>
#   include <lwip/ip_addr.h>
#   include "random.h"
#else 
#   include <sys/socket.h>
#   include <netinet/in.h>
#   include <arpa/inet.h>
#   include <ifaddrs.h>
#   include <netdb.h>
#   include <fcntl.h>
#endif

#include <time.h>
#include "nanosip.h"
#include "md5.h"

static char tmpstr[512];
static char resp_buf[1024];
static char in_buf[1024];

enum {
    WO_AUTH = 0,
    WITH_AUTH
};

static int pr_st[SIP_DLG_NST] = {0};
#define PRINT_STATE(X) {if (!pr_st[(X)]) {pr_st[(X)]=1; printf("DLG_STATE: "# X"\r\n");}}
#define CLR_PRINT_STATE() memset(pr_st, 0, sizeof(pr_st))

extern int rtp_start(sipdialog_t *dlg);
extern int rtp_stop(sipdialog_t *dlg);

/*
 *
 */
void nanosip_sleep_ms(int ms) {
#ifndef OS_LINUX
#else 
    usleep(ms*1000);
#endif    
}

/*
 *
 */
static int valid_ip(unsigned char *ip) {
    // Multicast
    if ((ip[0] >= 224) && (ip[0] <= 239))
        return 0;

    // Experimental
    if (ip[0] >= 240)
        return 0;

    // Loopback
    if (ip[0] == 127)
        return 0;

    // Broadcast
    if ((ip[0] == 0xFF) &&
        (ip[1] == 0xFF) &&
        (ip[2] == 0xFF) &&
        (ip[3] == 0xFF))
        return 0;

    // Все нули
    if ((ip[0] == 0) &&
        (ip[1] == 0) &&
        (ip[2] == 0) &&
        (ip[3] == 0))
        return 0;

    return 1;
}

/*
 *
 */
static char *parse_ip(char *str, unsigned char *ip) {
    int ip_pos = 0;
    int ip_letter = -1;

    if (*str == 0) {
        return NULL;
    }

    while (1) {
        if ((*str >= '0') && (*str <= '9')) {
            if (ip_letter < 0)
                ip_letter = 0;
            ip_letter = ip_letter*10 + ((*str) - '0');
            if (ip_letter > 255)
                return str;
        } else if (*str == '.') {
            if (ip_letter < 0)
                return str;
            ip[ip_pos] = ip_letter;
            ip_letter = -1;
            if (++ip_pos > 3)
                return str;
        } else if (*str == '\000') {
            if ((ip_letter < 0) && (ip_pos >= 4))
                return NULL;
            else if (ip_letter < 0)
                return str;
            ip[ip_pos++] = ip_letter;
            if (ip_pos < 4)
                return str;
            else
                return NULL;
        } else if ((*str == ' ') || (*str == '\t')) {
        } else
            return str;
        str++;
    }
}

/*
 *
 */
int nanosip_validate_sip_uri(char *url, char *pname, char *pip, int *pport) {
    char *c, *str_ip, *str_port, *s;
    static char purl[SIP_NAME_MAXLENGHT];
    unsigned char ip[4];
    int n, port_i;
    int err = 0;

    memset(purl, 0, sizeof(purl));

    if (strlen(url) > SIP_NAME_MAXLENGHT) {
        return -1;
    }

    strcpy(purl, url);

    if (purl[0] == 0) {
        return -1;
    }

    str_ip = strchr(purl, '@');
    str_port = strchr(purl,':');

    if (!str_ip) {
        err = -1;
        goto err_exit;
    }

    *str_ip++ = 0; 
    *str_port = 0; 

    if (pname) {
        strcpy(pname, purl);
    }
    
    if (NULL != (c = parse_ip(str_ip, ip))) {
        err = -2;
        goto err_exit;
    }

    if (!valid_ip(ip)) {
        err = -3;
        goto err_exit;
    }

    if (pip) {
        memcpy(pip, ip, sizeof(ip));
    }

    if (str_port) {
        *str_port++ = 0;
        s = str_port;
        n = 0;
        while (*str_port) {
            if (!isdigit(*str_port)) {
                err = -4;
                goto err_exit;
            }
            str_port++;
            if (++n > 5) {
                err = -5;
                goto err_exit;
            }
        }
        port_i = strtoul(s,0,10);

        if ((port_i < 1024) || (port_i > 65535)) {
            err = -6;
            goto err_exit;
        }
        if (pport) {
            *pport = port_i;
        }
    } else {
        if (pport) {
            *pport = DEF_SIP_PORT;
        }
    }

err_exit:
    return err;
}


/*
 *
 */
int nanosip_create_socket(sipdialog_t *dlg) {
    int ret;
    struct sockaddr_in addr;
    int sockfd = -1;
    uint16_t port = dlg->local_sip_port;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    ret = bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret) {
        printf("Failed to bind socket\r\n");
        return -1;
    }
    //fcntl(sockfd, F_SETFL, O_NONBLOCK);
    dlg->sockfd = sockfd;

    return sockfd;
}

/*
 *
 */
void nanosip_set_socket_tm(sipdialog_t *dlg, int tm_ms) {
    struct timeval tv;
    tv.tv_sec = tm_ms/1000;
    tv.tv_usec = (tm_ms % 1000)*1000;
    setsockopt(dlg->sockfd, SOL_SOCKET, SO_RCVTIMEO, (void *)&tv, sizeof(tv));
}

/*
 *
 */
int nanosip_set_blocking(sipdialog_t *dlg, int onoff) {
    int fl = fcntl(dlg->sockfd, F_GETFL, 0);
    if (onoff) fl |= O_NONBLOCK;
    else fl &= ~O_NONBLOCK;

    return fcntl(dlg->sockfd, F_SETFL, fl | O_NONBLOCK);
}

/*
 *
 */
void nanosip_destroy_socket(sipdialog_t *dlg) {
    close(dlg->sockfd);
}

/*
 *
 */
int nanosip_create_endpoint(ep_t *ep, uint8_t ip[4], uint16_t port) {
    memcpy(ep->ip, ip, sizeof(ip));
    ep->port = port;
    ep->err = 0;
}

/*
 *
 */
int nanosip_send_packet(sipdialog_t *dlg, char *data, int len) {
    struct sockaddr_in addr;
    uint8_t ip[4], *pip;
    uint16_t port = dlg->ep_sip.port;
    memset(&addr, 0, sizeof(addr));
#ifndef OS_LINUX    
    ip4_addr_t ipaddr;
    IP4_ADDR(&ipaddr, dlg->ep_sip.ip[0], dlg->ep_sip.ip[1], dlg->ep_sip.ip[2], dlg->ep_sip.ip[3]);
    addr.sin_addr.s_addr = ipaddr.addr;
#else 
    IP4_ADDR(addr.sin_addr.s_addr, dlg->ep_sip.ip[0], dlg->ep_sip.ip[1], dlg->ep_sip.ip[2], dlg->ep_sip.ip[3]);
#endif    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    return sendto(dlg->sockfd, data, len, MSG_DONTWAIT, (struct sockaddr *)&addr, sizeof(addr));
}

/*
 *
 */
uint8_t *nanosip_recv_packet(sipdialog_t *dlg, int *len) {
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    int cnt;
    cnt = recvfrom(dlg->sockfd, in_buf, sizeof(in_buf), 0, 
                  (struct sockaddr *) &addr, &addrlen);
    if (cnt > 0) {
        if (len) *len = cnt;
        return in_buf;
    }
    else return NULL;
}

/*
 *
 */
uint8_t *nanosip_recv_packet_tm(sipdialog_t *dlg, int *len, int ticks) {
    uint8_t *pdata;

    nanosip_set_socket_tm(dlg, 10);
    nanosip_set_blocking(dlg, 0);

    do {
        pdata = nanosip_recv_packet(dlg, len);
        if (!pdata && !ticks) {
            //printf("Failed to recv packet\r\n");
            nanosip_set_blocking(dlg, 1);
            return NULL;
        }
        nanosip_sleep_ms(100);
        ticks--;
    } while (!pdata);

    nanosip_set_blocking(dlg, 1);

    return pdata;
}

/*
 *
 */
static int nanosip_rtp_start(sipdialog_t *dlg) {
    return rtp_start(dlg); // must return 0 on success
}

/*
 *
 */
static int nanosip_rtp_stop(sipdialog_t *dlg) {
    return rtp_stop(dlg); // must return 0 on success
}

/*
 *
 */
static void nanosip_media_start(sipdialog_t *dlg) {
    dlg->rem_rtp_port = dlg->req.rem_rtp_port;
    if (dlg->call_media_active == 0) {
        dlg->call_media_active = !nanosip_rtp_start(dlg);
    }
}

/*
 *
 */
static void nanosip_media_stop(sipdialog_t *dlg) {
    if (dlg->call_media_active) {
        dlg->call_media_active = nanosip_rtp_stop(dlg);
    }
}

/*
 *
 */
void nanosip_rand(uint8_t *buf, int len) {
#ifndef OS_LINUX
    uint8_t *p = buf;
    int rlen = len / sizeof(uint32_t);
    int prlen = len % sizeof(uint32_t);
    int i = 0;
    uint32_t val;
    uint32_t *pb = (uint32_t *)buf;
    for (i = 0;i < rlen;i++) {
        pb[i] = random_number();
    }
    p += i*sizeof(uint32_t);
    val = random_number();
    for (i = 0;i < prlen;i++) {
        *p++ = (val >> (8*i)); 
    }
    #error !!!DEFINE RAND HERE
#else 
    FILE *fp = fopen("/dev/urandom", "rb");
    if (fp != NULL) {
        fread(buf, 1, len, fp);
        fclose(fp);    
    }
#endif    
}

/*
 *
 */
void nanosip_gen_rndstr(char *str, uint8_t len) {
    uint8_t ch, idx;
    idx = 0;

    while (idx < len) {
        nanosip_rand(&ch, 1);
        ch = ch % 16;
        if (ch < 10) {
            str[idx] = '0' + ch;
        } else {
            str[idx] = 'a' + ch - 10;
        }
        idx++;
    }

    str[len] = '\0';
}

/*
 *
 */
void nanosip_gen_branch(sipdialog_t *dlg) {
    nanosip_gen_rndstr(dlg->res.branch, 32);
}

/*
 *
 */
void nanosip_gen_callid(sipdialog_t *dlg) {
    nanosip_gen_rndstr(dlg->res.callid, 32);
}

/*
 *
 */
void nanosip_gen_fromtag(sipdialog_t *dlg) {
    nanosip_gen_rndstr(dlg->res.from_tag, 32);
}

/*
 *
 */
void nanosip_gen_totag(sipdialog_t *dlg) {
    nanosip_gen_rndstr(dlg->res.to_tag, 32);
}

/*
 *
 */
void nanosip_reg_cb(sipdialog_t *dlg) {

}

/*
 *
 */
void nanosip_early_media_cb(sipdialog_t *dlg) {
    
}

/*
 *
 */
void nanosip_ret_code_cb(sipdialog_t *dlg, int code) {

    switch(code) {
        case 180:
        break;
        case 404:
            printf("navailable here\r\n");
        break;
        case 486:
            printf("Busy here\r\n");
        break;
        case 487:
            printf("Canceled\r\n");
        break;
        case 503:
            printf("Unavailable service\r\n");
        break;
    }
}

/*
 *
 */
void nanosip_confirmed_cb(sipdialog_t *dlg) {
    // start RTP here
    nanosip_media_start(dlg);

    if (dlg->dlg_connected_cb) {
        dlg->dlg_connected_cb(0);
    }
}

/*
 *
 */
void nanosip_disconnected_cb(sipdialog_t *dlg) {
    // stop RTP here
    if (dlg->dlg_finished_cb) {
        dlg->dlg_finished_cb(0);
    }
    nanosip_media_stop(dlg);
}

/*
 *
 */
void nanosip_trying_cb(sipdialog_t *dlg) {
    if (dlg->dlg_calling_cb) {
        dlg->dlg_calling_cb(0);
    }
}

/*
 *
 */
void nanosip_info_dtmf_cb(sipdialog_t *dlg, uint8_t *data, int *pdigit) {
    int digit = -1;
    *pdigit = -1;
    uint8_t *p = strstr(data, "application/dtmf-relay");
    if (!p) return;
    p = strstr(data, "Signal=");
    if (!p) return;
    p += 7;
    while(*p == ' ') p++;
    digit = p[0];

    *pdigit = digit;
    // from rtp
    dtmf_digit_action(digit);
}

/*
 *
 */
void nanosip_init_dialog(sipdialog_t *dlg) {
    uint8_t i;

    dlg->cseq = dlg->res.cseq = 1;
    nanosip_gen_rndstr(dlg->res.callid, 32);
    nanosip_gen_rndstr(dlg->res.branch, 32);
    nanosip_gen_rndstr(dlg->res.from_tag, 32);

    memset(dlg->realm, 0, sizeof(dlg->realm));
    memset(dlg->nonce, 0, sizeof(dlg->nonce));
    memset(dlg->direct_uri, 0, sizeof(dlg->direct_uri));
    dlg->registered = 0;
    dlg->call_state = CALL_STATE_NONE;
    dlg->state = SIP_DLG_INIT;
    dlg->reinvite = 0;
}

/*
 *
 */
void nanosip_clean_dialog(sipdialog_t *dlg) {
    nanosip_gen_rndstr(dlg->res.callid, 32);
    nanosip_gen_rndstr(dlg->res.branch, 32);
    nanosip_gen_rndstr(dlg->res.from_tag, 32);

    memset(&dlg->req, 0, sizeof(re_t));
    memset(dlg->realm, 0, sizeof(dlg->realm));
    memset(dlg->nonce, 0, sizeof(dlg->nonce));
    memset(dlg->direct_uri, 0, sizeof(dlg->direct_uri));
}

/*
 *
 */
int nanosip_is_all_print(char *str) {
    int i;
    for(i = 0; i <= strlen(str); i++) {
        if (!isprint(str[i])) return 0;
    }
    return 1;
}

/*
 *
 */
void nanosip_dialog_request(sipdialog_t *dlg, char *pb, char *met, 
                            int auth, char *content) {
    int l = 0;
    int len = 0;
    char hash1[33];
    char hash2[33];
    char *domain = NULL;
    int direct_call = 0;

    if (strlen(dlg->domain) > 0 && nanosip_is_all_print(dlg->domain)) {
        domain = dlg->domain;
    } else {
        if (strlen(dlg->servip_str) <= 0) {
            ip_to_str(dlg->servip_str, dlg->servip);
        }
        domain = dlg->servip_str;
    }

    if (content) len = strlen(content);

    dlg->last_method = nanosip_get_request_method(met);

    if (dlg->last_method != SIP_METHOD_REGISTER) {
        if (nanosip_validate_sip_uri(dlg->remname, NULL, NULL, NULL) != 0) {
            sprintf(dlg->direct_uri, "%s@%d.%d.%d.%d", dlg->remname,
                    dlg->servip[0], dlg->servip[1], dlg->servip[2], dlg->servip[3]);
        } else {
            direct_call = 1;
            strcpy(dlg->direct_uri, dlg->remname);
        }
    }

    if (dlg->last_method == SIP_METHOD_REGISTER) {
        l += sprintf(pb+l, "%s sip:%s SIP/2.0\r\n", met, domain);
    } else {
        l += sprintf(pb+l, "%s sip:%s SIP/2.0\r\n", met, dlg->direct_uri);
    }     
    // Via
    l += sprintf(pb+l,"Via: SIP/2.0/UDP %d.%d.%d.%d:%d;",
                 dlg->localip[0], dlg->localip[1], dlg->localip[2], 
                 dlg->localip[3], dlg->local_sip_port);
    l += sprintf(pb+l, "branch=z9hG4bK%s;rport\r\n",dlg->res.branch);

    // Route
    if (dlg->last_method == SIP_METHOD_REGISTER) {
         l += sprintf(pb+l, "Route: <sip:%d.%d.%d.%d;lr>\r\n", dlg->servip[0], dlg->servip[1], dlg->servip[2], dlg->servip[3]);
    }

    // From
    l += sprintf(pb+l, "From: \"%s\"<sip:",dlg->uastring);
    if (direct_call) {
        l += sprintf(pb+l, "%s@%d.%d.%d.%d>;",dlg->locname, 
             dlg->localip[0], dlg->localip[1], dlg->localip[2], dlg->localip[3]);
    } else {
        l += sprintf(pb+l, "%s@%s>;",dlg->locname, domain);
    }
    l += sprintf(pb+l, "tag=%s\r\n", dlg->res.from_tag); // UAC generates FROM tag

    // To
    if (dlg->last_method == SIP_METHOD_REGISTER) {
        l += sprintf(pb+l, "To: \"%s\"<sip:",dlg->uastring);
        l += sprintf(pb+l, "%s@%s>\r\n",dlg->locname, domain);
    } else {
        l += sprintf(pb+l, "To: <sip:%s>",dlg->direct_uri);
        if (dlg->last_method != SIP_METHOD_INVITE || 
            (dlg->last_method == SIP_METHOD_INVITE && dlg->reinvite)) {
            l += sprintf(pb+l, ";tag=%s", dlg->req.to_tag); // UAS generates TO tag 
        }
        l += sprintf(pb+l, "\r\n");
    }
    
    // Call-ID
    l += sprintf(pb+l, "Call-ID: %s\r\n",dlg->res.callid);
    // CSeq
    l += sprintf(pb+l, "CSeq: %d %s\r\n",dlg->cseq, met);
    // Contact
    l += sprintf(pb+l, "Contact: \"%s\"<sip:",dlg->uastring);
    l += sprintf(pb+l, "%s@%d.%d.%d.%d:%d;ob>\r\n",dlg->locname, 
                 dlg->localip[0], dlg->localip[1], dlg->localip[2], 
                 dlg->localip[3], dlg->local_sip_port);
    // Max fwd
    l += sprintf(pb+l, "%s","Max-Forwards: 70\r\n");

    // Expires
    if (dlg->last_method == SIP_METHOD_REGISTER) {
        l += sprintf(pb+l, "Expires: %d\r\n",dlg->exp_time);
    }
    // Allow
    l += sprintf(pb+l, "Allow: INVITE, ACK, CANCEL, BYE, REGISTER, INFO\r\n");
    // UA
    l += sprintf(pb+l, "User-Agent: %s\r\n", dlg->uastring);

    // Auth
    if (auth) {
        uint8_t md5_digest[16];
        int i;
        l += sprintf(pb+l, "Authorization: Digest username=\"");
        l += sprintf(pb+l, "%s\", realm=\"%s\", nonce=\"%s\", ",
                     dlg->locname, dlg->realm, dlg->nonce);
        if (dlg->last_method == SIP_METHOD_REGISTER) {
            l += sprintf(pb+l, "uri=\"sip:%d.%d.%d.%d\", ",
                     dlg->servip[0], dlg->servip[1], dlg->servip[2], dlg->servip[3]);
        } else if (dlg->last_method == SIP_METHOD_INVITE) {
            l += sprintf(pb+l, "uri=\"sip:%s\", ",dlg->direct_uri);
        }

        sprintf(tmpstr, "%s:%s:%s",dlg->locname, dlg->realm, dlg->pass);

        md5((uint8_t *)tmpstr, strlen(tmpstr), md5_digest);
        for (i = 0; i < 16; i++) {
            sprintf(&hash1[i * 2], "%2.2x", md5_digest[i]);
        }

        if (dlg->last_method == SIP_METHOD_REGISTER) {
            sprintf(tmpstr, "%s:sip:%d.%d.%d.%d", met,
                dlg->servip[0], dlg->servip[1], dlg->servip[2], dlg->servip[3]);
        } else if (dlg->last_method == SIP_METHOD_INVITE) {
            sprintf(tmpstr, "%s:sip:%s", met, dlg->direct_uri);
        }

        md5((uint8_t *)tmpstr, strlen(tmpstr), md5_digest);
        for (i = 0; i < 16; i++) {
            sprintf(&hash2[i * 2], "%2.2x", md5_digest[i]);
        }

        sprintf(tmpstr, "%s:%s:%s", hash1, dlg->nonce, hash2);
        md5((uint8_t *)tmpstr, strlen(tmpstr), md5_digest);
        for (i = 0; i < 16; i++) {
            sprintf(&tmpstr[i * 2], "%2.2x", md5_digest[i]);
        }
        l += sprintf(pb+l, "response=\"%s\", ", tmpstr);
        l += sprintf(pb+l, "algorithm=MD5\r\n");
    }

    if (dlg->last_method == SIP_METHOD_INVITE) {
        l += sprintf(pb+l, "Content-Type: application/sdp\r\n");
    }

    // Content length
    l += sprintf(pb+l, "Content-Length: %d\r\n\r\n", len);

    if (len) {
        l += sprintf(pb+l, "%s\r\n", content);
    }
}

/*
 *
 */
void nanosip_dialog_response(sipdialog_t *dlg, char *pb, int code, 
                             char *reason, char *content) {
    int l = 0;
    int len = 0;
    
    if (content) len = strlen(content);

    l += sprintf(pb+l, "SIP/2.0 %d %s\r\n", code, reason);
    // Via
    l += sprintf(pb+l, "Via: SIP/2.0/UDP %s;", dlg->req.via);
    l += sprintf(pb+l, "branch=%s;rport\r\n",dlg->req.branch);
    // From
    l += sprintf(pb+l, "From: %s;",dlg->req.from);
    l += sprintf(pb+l, "tag=%s\r\n", dlg->req.from_tag);
    // To
    l += sprintf(pb+l, "To: %s;",dlg->req.to);
    l += sprintf(pb+l, "tag=%s\r\n",dlg->req.to_tag); 
    // Call-ID
    l += sprintf(pb+l, "Call-ID: %s\r\n",dlg->req.callid);
    // CSeq
    l += sprintf(pb+l, "CSeq: %d %s\r\n",dlg->req.cseq, dlg->req.method);
    // Contact
    l += sprintf(pb+l, "Contact: \"%s\"<sip:",dlg->uastring);
    l += sprintf(pb+l, "%s@%d.%d.%d.%d:%d>\r\n",dlg->locname, 
                 dlg->localip[0], dlg->localip[1], dlg->localip[2], 
                 dlg->localip[3], dlg->local_sip_port);
    // Maxfwd
    l += sprintf(pb+l, "%s","Max-Forwards: 70\r\n");

    // Allow
    l += sprintf(pb+l, "Allow: INVITE, ACK, CANCEL, BYE, REGISTER, INFO\r\n");
    // UA
    l += sprintf(pb+l, "User-Agent: %s\r\n", dlg->uastring);

    if (nanosip_get_request_method(dlg->req.method) == SIP_METHOD_INVITE) {
        l += sprintf(pb+l, "Content-Type: application/sdp\r\n");
    }

    // Content length
    l += sprintf(pb+l, "Content-Length: %d\r\n\r\n", len);

    if (len) {
        l += sprintf(pb+l, "%s\r\n", content);
    }
}

/*
 *
 */
void nanosip_gen_default_sdp(sipdialog_t *dlg, char *pb) {
    int l = 0;
    l += sprintf(pb+l, "v=0\r\n"
                       "o=- 0 0 IN IP4 %d.%d.%d.%d\r\n",
                 dlg->localip[0], dlg->localip[1], dlg->localip[2], dlg->localip[3]);
    l += sprintf(pb+l, "s=session\r\n"
                       "c=IN IP4 %d.%d.%d.%d\r\n",
                 dlg->localip[0], dlg->localip[1], dlg->localip[2], dlg->localip[3]);
    l += sprintf(pb+l,  "t=0 0\r\n"
                        "m=audio %d RTP/AVP 8 101\r\n"
                        "a=rtcp:%d IN IP4 %d.%d.%d.%d\r\n",
                        dlg->local_rtp_port, dlg->local_rtp_port + 1,
                        dlg->localip[0], dlg->localip[1], dlg->localip[2], dlg->localip[3]);
    
    l += sprintf(pb+l, "a=rtpmap:8 PCMA/8000\r\n"
                       "a=rtpmap:101 telephone-event/8000\r\n"
                       "a=sendrecv\r\n");

}

/*
 *
 */
int nanosip_parse_pkt(char *str, re_t *req) {
    char *p, *c;
    int request;

    request = !(0 == strncmp(str, "SIP/2.0 ", 8));
    memset(req, 0, sizeof(re_t));
    req->request = request;
    p = str; 

    if (request) {
        // Method
        c = req->method;
        while(*p != '\r' && *p != '\n' && *p != ' ') {*c++ = *p++;};
        // skip spaces
        while(*p == ' ')p++;
        // URI
        c = req->uri;
        while(*p != '\r' && *p != '\n' && *p != ' ') {*c++ = *p++;};
    } else {
        p += strlen("SIP/2.0 ");
        req->code = atoi(p);
    }

    // Via, branch
    if ((p = strstr(str, "Via: SIP/2.0/UDP ")) != NULL) {
        p += strlen("Via: SIP/2.0/UDP ");
        c = req->via;
        while(*p != '\r' && *p != '\n' && *p != ';') {*c++ = *p++;};

        if ((p = strstr(p, "branch=")) != NULL) {
            p += strlen("branch=");
            c = req->branch;
            while(*p != '\r' && *p != '\n' && *p != ';') {*c++ = *p++;};
        }
    }
    // From, tag
    if ((p = strstr(str, "From: ")) != NULL) {
        p += strlen("From: ");
        c = req->from;
        while(*p != '\r' && *p != '\n' && *p != ';') {*c++ = *p++;};

        if ((p = strstr(p, "tag=")) != NULL) {
            p += strlen("tag=");
            c = req->from_tag;
            while(*p != '\r' && *p != '\n' && *p != ';') {*c++ = *p++;};
        }
    }
    // To, tag
    if ((p = strstr(str, "To: ")) != NULL) {
        p += strlen("To: ");
        c = req->to;
        while(*p != '\r' && *p != '\n' && *p != ';') {*c++ = *p++;};

        if ((p = strstr(p, "tag=")) != NULL) {
            p += strlen("tag=");
            c = req->to_tag;
            while(*p != '\r' && *p != '\n' && *p != ';') {*c++ = *p++;};
        }
    }
    // Call-ID
    if ((p = strstr(str, "Call-ID: ")) != NULL) {
        p += strlen("Call-ID: ");
        c = req->callid;
        while(*p != '\r' && *p != '\n' && *p != ';') {*c++ = *p++;};
    }
    // Contact
    if ((p = strstr(str, "Contact: ")) != NULL) {
        p += strlen("Contact: ");
        c = req->contact;
        while(*p != '\r' && *p != '\n' && *p != ';') {*c++ = *p++;};
    }
    // CSeq
    if ((p = strstr(str, "CSeq: ")) != NULL) {
        p += strlen("CSeq: ");
        req->cseq = atoi(p);
    }
    // Auth
    if ((p = strstr(str, "WWW-Authenticate: ")) != NULL) {
        p += strlen("WWW-Authenticate: ");
        c = req->auth;
        while(*p != '\r' && *p != '\n' && *p != ';') {*c++ = *p++;};
    }
    // SDP
    if (strstr(str, "Content-Type: application/sdp")) {
        p = strstr((char *)str, "m=audio ") + strlen("m=audio ");
        req->rem_rtp_port = atoi(p);
    }

    return 0;
}

/*
 *
 */
int nanosip_get_aut_param(re_t *req, char *realm, char *nonce) {
    char *p, *c;
    int ret = -1;
    
    if (realm && (p = strstr(req->auth, "realm=\"")) != NULL) {
        p += strlen("realm=\"");            
        c = realm;
         while(*p != '\r' && *p != '\n' && *p != ',' && *p != '\"') {*c++ = *p++;};
         *c = 0;
         ret++;
    }

    if (nonce && (p = strstr(req->auth, "nonce=\"")) != NULL) {
        p += strlen("nonce=\""); 
        c = nonce;
         while(*p != '\r' && *p != '\n' && *p != ',' && *p != '\"') {*c++ = *p++;};
         *c = 0;
         ret++;
    }
    return ret;
}

/*
 *
 */
int nanosip_get_request_method(char *method) {
    if (!strcmp(method, "INVITE")) return SIP_METHOD_INVITE;
    else if (!strcmp(method, "REGISTER")) return SIP_METHOD_REGISTER;
    else if (!strcmp(method, "INFO")) return SIP_METHOD_INFO;
    else if (!strcmp(method, "BYE")) return SIP_METHOD_BYE;
    else if (!strcmp(method, "ACK")) return SIP_METHOD_ACK;
    else if (!strcmp(method, "MESSAGE")) return SIP_METHOD_MESSAGE;
    else if (!strcmp(method, "UPDATE")) return SIP_METHOD_UPDATE;
    else return SIP_METHOD_NONE;
}

/*
 *
 */
int nanosip_get_response_code(re_t *res) {
    return res->code;
}

/*
 *
 */
void nanosip_copy_request(char *pb, char *met, re_t *req, re_t *res) {
    int l = 0;
    l += sprintf(pb+l, "%s sip:%s SIP/2.0\r\n", met, req->uri);
    l += sprintf(pb+l, "Via: SIP/2.0/UDP %s;branch=%s;rport\r\n", 
                req->via, req->branch);
    l += sprintf(pb+l, "%s\r\n", "Max-Forwards: 70");
    l += sprintf(pb+l, "To: %s;tag=%s\r\n", 
                 res ? res->to : req->to, res ? res->to_tag : req->to_tag);
    l += sprintf(pb+l, "From: %s;tag=%s\r\n", req->from, req->from_tag);
    l += sprintf(pb+l, "Call-ID: %s\r\n", req->callid);
    l += sprintf(pb+l, "CSeq: %d %s\r\n", req->cseq, met);
    strcat(pb, "Content-Length: 0\r\n\r\n");
}

/*
 *
 */
void nanosip_invite_response(char *pb, re_t *req) {
    nanosip_copy_request(pb, "ACK", req, NULL);
}

/*
 *
 */
void nanosip_ack_response(char *pb, re_t *req) {
    nanosip_copy_request(pb, "ACK", req, NULL);
}

/*
 *
 */
void nanosip_print_re(re_t *req) {
    printf("**************************************\r\n");
    printf("Method: %s\r\n", req->method);
    printf("URI: %s\r\n", req->uri);
    printf("Via: %s;branch=%s\r\n", req->via, req->branch);
    printf("From: %s;tag=%s\r\n", req->from, req->from_tag);
    printf("To: %s;tag=%s\r\n", req->to, req->to_tag);
    printf("Call-ID: %s\r\n", req->callid);
    printf("Contact: %s\r\n", req->contact);
    printf("CSeq: %d\r\n", req->cseq);
    printf("Auth: %s\r\n", req->auth);
    printf("**************************************\r\n");
}

/*
 *
 */
int nanosip_register(sipdialog_t *dlg) {
    uint8_t *pdata;
    int  len;
    int res, resp = -1;
    int tm = 20;

    if (!valid_ip(dlg->servip)) {
        goto on_err;
    }

    printf("Trying to Register on: %i.%i.%i.%i\r\n", dlg->servip[0], dlg->servip[1], dlg->servip[2], dlg->servip[3]);

    dlg->cseq++;
    nanosip_gen_branch(dlg);
    nanosip_create_endpoint(&dlg->ep_sip, dlg->servip, (uint16_t)dlg->serv_sip_port);
    nanosip_dialog_request(dlg, resp_buf, "REGISTER", WO_AUTH, NULL);
    res = nanosip_send_packet(dlg, resp_buf, strlen(resp_buf));
    if (res < 0) {
        printf("Failed to send packet\r\n");
        goto on_err;
    }

    nanosip_set_socket_tm(dlg, 10);
    nanosip_set_blocking(dlg, 0);

    do {
        pdata = nanosip_recv_packet(dlg, &len);
        if (!pdata && !tm) {
            printf("REG: Failed to recv packet 1\r\n");
            nanosip_set_blocking(dlg, 1);
            goto on_err;
        }
        nanosip_sleep_ms(100);
        tm--;
    } while (!pdata);

    nanosip_parse_pkt(pdata, &dlg->req);
    //nanosip_print_re(&dlg->req);
    if ((resp = nanosip_get_response_code(&dlg->req)) != 401) {
        goto on_err;
    }
    
    dlg->cseq++;
    nanosip_gen_branch(dlg);
    nanosip_get_aut_param(&dlg->req, dlg->realm, dlg->nonce);
    nanosip_dialog_request(dlg, resp_buf, "REGISTER", WITH_AUTH, NULL);
    //printf("REG 2: %s\r\n", resp_buf);
    res = nanosip_send_packet(dlg, resp_buf, strlen(resp_buf));
    if (res < 0) {
        printf("Failed to send packet 2\r\n");
        goto on_err;
    }

    tm = 20;
    do {
        pdata = nanosip_recv_packet(dlg, &len);
        if (!pdata && !tm) {
            printf("REG: Failed to recv packet 2\r\n");
            nanosip_set_blocking(dlg, 1);
            goto on_err;
        }
        nanosip_sleep_ms(100);
        tm--;
    } while (!pdata);

    nanosip_set_blocking(dlg, 1);

    nanosip_parse_pkt(pdata, &dlg->req);
    //nanosip_print_re(&dlg->req);
    if ((resp = nanosip_get_response_code(&dlg->req)) != 200) {
        goto on_err;
    }
    dlg->registered = 1;

    printf("Registration succeed\r\n");

    return 0;
on_err:

    printf("Registration failed with code: %d\r\n", resp);
    return -1;    
}


//*******************************************************
static re_t temp_re;
void nanosip_run(sipdialog_t *dlg) {
    int msg = dlg->msg;
    int state = dlg->state;
    uint8_t ip[4];
    uint32_t port;
    //dlg->msg = SIP_DLG_MSG_NONE;
    
    switch(state) {
        case SIP_DLG_INIT: PRINT_STATE(SIP_DLG_INIT);
            nanosip_init_dialog(dlg);
            dlg->state = SIP_DLG_IDLE;
        break;
        case SIP_DLG_IDLE: PRINT_STATE(SIP_DLG_IDLE); 
            if (msg) {
                while (nanosip_recv_packet_tm(dlg, NULL, 10)); // purge rx socket
            }

            if (msg == SIP_DLG_MSG_CALL) {
                dlg->last_code = 0;
                dlg->reinvite = 0;
                dlg->msg = SIP_DLG_MSG_NONE;
                dlg->state = SIP_DLG_CALLING;
            } else if (msg == SIP_DLG_MSG_REG) {
                dlg->state = SIP_DLG_REG_S1;
                dlg->msg = SIP_DLG_MSG_NONE;
            }
            
            //nanosip_sleep_ms(100);
        break;
        case SIP_DLG_REG_S1: PRINT_STATE(SIP_DLG_REG_S1);
            if (nanosip_register(dlg) == 0) {
                dlg->registered = 1;
                nanosip_reg_cb(dlg);
            } else {
                dlg->registered = 0;
                nanosip_sleep_ms(1000);
            }
            dlg->state = SIP_DLG_IDLE;
            //nanosip_sleep_ms(100);
        break;
        case SIP_DLG_CALLING: PRINT_STATE(SIP_DLG_CALLING);
            if (dlg->call_state >= CALL_STATE_CALLING && 
                dlg->call_state < CALL_STATE_DISCONNECTED) {
            } else {
                if (!dlg->reinvite) {
                    dlg->cseq++;
                    nanosip_gen_branch(dlg);
                } else {
                    nanosip_sleep_ms(1000*4); // delay ~4 sec
                }

                if (nanosip_validate_sip_uri(dlg->remname, dlg->direct_uri, ip, &port) == 0) {
                    nanosip_create_endpoint(&dlg->ep_sip, ip, (uint16_t)port);
                } else {
                    nanosip_create_endpoint(&dlg->ep_sip, dlg->servip, (uint16_t)dlg->serv_sip_port);
                }

                printf("Invite to: %s\r\n", dlg->remname);
                // INVITE without AUTH
                nanosip_gen_default_sdp(dlg, tmpstr);
                nanosip_dialog_request(dlg, resp_buf, "INVITE", WO_AUTH, tmpstr);
                int res = nanosip_send_packet(dlg, resp_buf, strlen(resp_buf));
                if (res < 0) {
                    printf("Failed to send packet\r\n");
                    dlg->state = SIP_DLG_IDLE;
                    break;
                }
                dlg->call_state = CALL_STATE_CALLING;
                dlg->state = SIP_DLG_CALLING_S1;
                nanosip_set_socket_tm(dlg, 100);
            }
        break;
        case SIP_DLG_CALLING_S1: { PRINT_STATE(SIP_DLG_CALLING_S1);
            int len;
            int code;
            uint8_t *pdata = nanosip_recv_packet_tm(dlg, &len, 10); // ~1 sec timeout
            if (!pdata) {
                if (msg == SIP_DLG_MSG_HANGUP) {
                    dlg->msg = SIP_DLG_MSG_NONE;
                    dlg->cseq++;
                    nanosip_dialog_request(dlg, resp_buf, "CANCEL", WO_AUTH, NULL);
                    nanosip_send_packet(dlg, resp_buf, strlen(resp_buf));
                    dlg->call_state = CALL_STATE_DISCONNECTING;
                }
                break;
            }
            nanosip_parse_pkt(pdata, &dlg->req);
            code = nanosip_get_response_code(&dlg->req);
            dlg->last_code = code;
            printf("RESP CODE: %d\r\n",code);

            nanosip_ret_code_cb(dlg, code);

            switch (code) {
                case 100: // trying
                    dlg->call_state = CALL_STATE_TRYING;
                    nanosip_trying_cb(dlg);
                    break;
                case 180: // early media
                    dlg->call_state = CALL_STATE_EARLY;
                    nanosip_early_media_cb(dlg);
                    break;
                case 401: // unauthorized
                    // ACK
                    dlg->cseq++;
                    nanosip_gen_branch(dlg);
                    nanosip_get_aut_param(&dlg->req, dlg->realm, dlg->nonce);
                    strcpy(dlg->req.uri, dlg->res.uri);
                    nanosip_ack_response(resp_buf, &dlg->req);
                    nanosip_send_packet(dlg, resp_buf, strlen(resp_buf));
                    // INVITE with AUTH
                    dlg->cseq++;
                    nanosip_gen_branch(dlg);
                    nanosip_gen_default_sdp(dlg, in_buf);
                    nanosip_dialog_request(dlg, resp_buf, "INVITE", WITH_AUTH, in_buf);
                    nanosip_send_packet(dlg, resp_buf, strlen(resp_buf));
                    break;
                case 491: // request pending
                    dlg->reinvite = 1;
                    dlg->state = SIP_DLG_CALLING;
                    dlg->call_state = CALL_STATE_NONE;
                    break;   
                case 481: // transaction does not exist
                case 486: // busy
                case 487: // canceled
                case 503: // service unavailable
                case 404: // undefined
                case 603: // decline
                    strcpy(dlg->req.uri, dlg->res.uri);
                    nanosip_ack_response(resp_buf, &dlg->req);
                    nanosip_send_packet(dlg, resp_buf, strlen(resp_buf));
                    dlg->call_state = CALL_STATE_DISCONNECTED;
                    dlg->state = SIP_DLG_DISCONNECTED;
                    break;    
                case 500: // server error
                    dlg->call_state = CALL_STATE_DISCONNECTED;
                    dlg->state = SIP_DLG_IDLE;
                break; 
                case 200: // OK
                    if (dlg->call_state == CALL_STATE_DISCONNECTING) {
                        // some weird UACs respond 200 to CANCEL before 487...
                        break;   
                    }

                    strcpy(dlg->req.uri, dlg->res.uri);
                    nanosip_ack_response(resp_buf, &dlg->req);
                    nanosip_send_packet(dlg, resp_buf, strlen(resp_buf));
                    dlg->call_state = CALL_STATE_CONFIRMED;
                    dlg->state = SIP_DLG_CONFIRMED;
                    dlg->reinvite = 0;

                    if (nanosip_validate_sip_uri(dlg->remname, dlg->direct_uri, ip, &port) == 0) {
                        nanosip_create_endpoint(&dlg->ep_rtp, ip, (uint16_t)port);
                    } else {
                        nanosip_create_endpoint(&dlg->ep_rtp, dlg->servip, (uint16_t)dlg->serv_sip_port);
                    }

                    nanosip_confirmed_cb(dlg);
                    nanosip_set_socket_tm(dlg, 100);
                    nanosip_set_blocking(dlg, 0);

                break;
                default:
                break;
            }
        } break;

        case SIP_DLG_CONFIRMED: { PRINT_STATE(SIP_DLG_CONFIRMED);
            int len;
            int code, method;
            uint8_t *pdata = nanosip_recv_packet_tm(dlg, &len, 10); // ~1 sec timeout

            // in case of error in RTP endpoint (5 sec no rx data) try to finish the call...
            if (dlg->ep_rtp.err) {
                if (dlg->call_state == CALL_STATE_CONFIRMED) {
                    dlg->msg = SIP_DLG_MSG_HANGUP;
                } else if (dlg->call_state == CALL_STATE_DISCONNECTING) {
                    dlg->call_state = CALL_STATE_DISCONNECTED;
                    dlg->state = SIP_DLG_DISCONNECTED;
                }
            }

            if (!pdata) {
                if (msg == SIP_DLG_MSG_HANGUP) {
                    dlg->msg = SIP_DLG_MSG_NONE;
                    dlg->cseq++;
                    nanosip_dialog_request(dlg, resp_buf, "BYE", WO_AUTH, NULL);
                    nanosip_send_packet(dlg, resp_buf, strlen(resp_buf));
                    dlg->call_state = CALL_STATE_DISCONNECTING;
                }
                break;
            }

            // copy to temp in case of ACK or incoming INVITE
            memset(&temp_re, 0, sizeof(re_t));
            memcpy(&temp_re, &dlg->req, sizeof(re_t));

            nanosip_parse_pkt(pdata, &dlg->req);
            code = nanosip_get_response_code(&dlg->req);
            dlg->last_code = code;
            method = nanosip_get_request_method(dlg->req.method);

            dlg->last_method = method;

            printf("REQ METHOD: %s\r\n", method?dlg->req.method:"NONE");
            if (!method) {
                printf("CODE: %d\r\n", code);
            }

            if (method == SIP_METHOD_ACK) {
                memcpy(&dlg->req, &temp_re, sizeof(re_t));
                break;
            }

            switch(method) {
                case SIP_METHOD_INVITE:
                    nanosip_gen_default_sdp(dlg, tmpstr);
                    nanosip_dialog_response(dlg, resp_buf, 200, "OK", tmpstr);
                    nanosip_send_packet(dlg, resp_buf, strlen(resp_buf));
                    // incoming INVITE with its FROM tag
                    memcpy(&dlg->req, &temp_re, sizeof(re_t));
                break;
                case SIP_METHOD_INFO: {
                    int digit;
                    nanosip_dialog_response(dlg, resp_buf, 200, "OK", NULL);
                    nanosip_send_packet(dlg, resp_buf, strlen(resp_buf));
                    nanosip_info_dtmf_cb(dlg, resp_buf, &digit);
                } break;
                case SIP_METHOD_BYE:
                    nanosip_dialog_response(dlg, resp_buf, 200, "OK", NULL);
                    nanosip_send_packet(dlg, resp_buf, strlen(resp_buf));
                    dlg->call_state = CALL_STATE_DISCONNECTED;
                    dlg->state = SIP_DLG_DISCONNECTED;
                break;
                default:
                    if (code == 200) {
                        if (dlg->call_state == CALL_STATE_DISCONNECTING) {
                            dlg->call_state = CALL_STATE_DISCONNECTED;
                            dlg->state = SIP_DLG_DISCONNECTED;
                            break;
                        }
                        strcpy(dlg->req.uri, dlg->res.uri);
                        nanosip_ack_response(resp_buf, &dlg->req);
                        nanosip_send_packet(dlg, resp_buf, strlen(resp_buf));
                    } 
                break;
            }
        } break;

        case SIP_DLG_DISCONNECTED:
            nanosip_set_blocking(dlg, 1);
            PRINT_STATE(SIP_DLG_DISCONNECTED);
            nanosip_disconnected_cb(dlg);
            dlg->state = SIP_DLG_CLOSE;
        break;

        case SIP_DLG_CLOSE:
            PRINT_STATE(SIP_DLG_CLOSE);
            nanosip_destroy_socket(dlg);
            nanosip_clean_dialog(dlg);
            dlg->cseq++;
            nanosip_create_socket(dlg);
            dlg->state = SIP_DLG_IDLE;
            CLR_PRINT_STATE();
        break;

        case SIP_DLG_DONE:
            PRINT_STATE(SIP_DLG_DONE);
            nanosip_sleep_ms(1000);
        break;
        default:break;
    }
    dlg->prev_state = state;
}

