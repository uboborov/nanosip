#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "nanosip.h"

extern char invite_pkt[];
extern char resp_401_pkt[];

static char resp_buf[900];
static char tmp_buf[512];

sipdialog_t dlg;
pthread_t thread_sip_dlg;

#ifdef OS_LINUX 
#include <ifaddrs.h>
#include <netdb.h>

#include <net/if.h>
#include <sys/ioctl.h>

int get_local_address(char *ifname, char *buf) {
    int fd;
    struct ifreq ifr;

    memset(buf, 0, 16);
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    /* I want to get an IPv4 IP address */
    ifr.ifr_addr.sa_family = AF_INET;
    /* I want an IP address attached to "eth0" */
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    /* Display result */
    sprintf(buf, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

    return 0;
}

uint32_t get_local_ip() {
    FILE *f;
    char line[256] , *p , *c;

    f = fopen("/proc/net/route" , "r");
     
    while(fgets(line , 256 , f)) {
        p = strtok(line , " \t");
        c = strtok(NULL , " \t");
        if(p != NULL && c != NULL) {
            if(strcmp(c , "00000000") == 0) {
                // default interface
                break;
            }
        }
    }

    fclose(f);
     
    //which family do we require , AF_INET or AF_INET6
    int fm = AF_INET;
    struct ifaddrs *ifaddr, *ifa;
    int family , s;
    char host[NI_MAXHOST];
 
    if (getifaddrs(&ifaddr) == -1) {
        return INADDR_ANY;
    }
 
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }
 
        family = ifa->ifa_addr->sa_family;
 
        if(strcmp( ifa->ifa_name , p) == 0) {
            if (family == fm) {
                s = getnameinfo(ifa->ifa_addr, (family == AF_INET) ? 
                                sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                                 host , NI_MAXHOST , NULL , 0 , NI_NUMERICHOST);
                 
                if (s != 0) {
                  freeifaddrs(ifaddr);
                  return INADDR_ANY;
                }
                struct sockaddr_in *in_addr = (struct sockaddr_in *)ifa->ifa_addr;
                freeifaddrs(ifaddr);
                return in_addr->sin_addr.s_addr;
            }
        }
    }
 
    freeifaddrs(ifaddr);
    return INADDR_ANY;
}
#endif

static void *sip_dlg_run(void *args) {
    sipdialog_t *dlg = (sipdialog_t *)args;

    printf("SIP dlg thread started!\r\n");

    while(1) {
        nanosip_run(dlg);
    }
}

int start_sip_dlg(sipdialog_t *dlg) {
    int result = pthread_create(&thread_sip_dlg, NULL, sip_dlg_run, (void *)dlg);
    if (result != 0) {
        printf("SIP dlg thread is not created\n");
        return -1;
    }
    return 0;
}

void update_dialog_remname(sipdialog_t *dlg, char *name, char *ip) {
   char *pip = NULL;
    pip = ip?ip:dlg->servip;
    uint8_t ip_addr[4];
    char *pname;
    
    if (nanosip_validate_sip_uri(name, dlg->direct_uri, ip_addr, NULL) == 0) {
        pip = ip_addr;
        pname = dlg->direct_uri;
    } else {
        pip = dlg->servip;
        pname = dlg->remname;
    }
    
    if (!pip) return;
    strcpy(dlg->remname, name);

    sprintf(dlg->res.uri, "%s@%d.%d.%d.%d", pname, pip[0], pip[1], pip[2], pip[3]);
}

void setup_test_config(sipdialog_t *dlg) {
    // SIP server
    dlg->servip[0] = 192;
    dlg->servip[1] = 168;
    dlg->servip[2] = 10;
    dlg->servip[3] = 100;
    dlg->serv_sip_port = 5060;
    // local
#ifndef OS_LINUX    
    dlg->localip[0] = 192;
    dlg->localip[1] = 168;
    dlg->localip[2] = 10;
    dlg->localip[3] = 107;
#else 
    uint32_t addr = get_local_ip();
    addr = ntohl(addr);
    dlg->localip[0] = (addr >> 24) & 0xFF;
    dlg->localip[1] = (addr >> 16) & 0xFF;
    dlg->localip[2] = (addr >> 8) & 0xFF;
    dlg->localip[3] = (addr >> 0) & 0xFF;
#endif    
    dlg->local_sip_port = 5060;
    dlg->local_rtp_port = 5760;
    dlg->exp_time = 3600;
    strcpy(dlg->locname, "888");
    strcpy(dlg->pass, "888");
    strcpy(dlg->uastring, "Addon3");
    // remote
    strcpy(dlg->remname, "444");

    ip_to_str(dlg->localip_str, dlg->localip);
    ip_to_str(dlg->servip_str,  dlg->servip);
    
    sprintf(dlg->res.uri, "sip:%s@%d.%d.%d.%d", dlg->remname,
            dlg->servip[0], dlg->servip[1], dlg->servip[2], dlg->servip[3]);

    update_dialog_remname(dlg, "444", dlg->servip);

}

int main(int argc, char *argv[]) {
    nanosip_init_dialog(&dlg);
    setup_test_config(&dlg);

    printf("Local IP : %d.%d.%d.%d\r\n", 
                 dlg.localip[0], dlg.localip[1], 
                 dlg.localip[2], dlg.localip[3]);

    printf("Remote IP: %d.%d.%d.%d\r\n", 
                 dlg.servip[0], dlg.servip[1], 
                 dlg.servip[2], dlg.servip[3]);
    
    if (nanosip_create_socket(&dlg) <= 0) {
        printf("Failed to create socket\r\n");
        exit(0);
    }

    start_sip_dlg(&dlg);

    while(1) {
        char *line = NULL;
        size_t len = 0;
        ssize_t read = 0;

        read = getline(&line, &len, stdin);
        if (read == -1)
            exit(0);
        if (strncmp(line, "reg", 3) == 0) dlg.msg = SIP_DLG_MSG_REG;
        else if (strncmp(line, "call", 4) == 0) {
            dlg.msg = SIP_DLG_MSG_CALL;
            if (line[4] == ':') {
                int i;
                for (i = 0;i < strlen(line);i++) {
                    if (line[i] == '\n' || line[i] == '\r') line[i] = 0;
                }
                update_dialog_remname(&dlg, line + 5, NULL);
            }
        }
        else if (strncmp(line, "hangup", 6) == 0) dlg.msg = SIP_DLG_MSG_HANGUP;
        else if (strncmp(line, "exit", 4) == 0) exit(0);

        printf("set: %s\r\n", line);
    }
    return 0;
}
