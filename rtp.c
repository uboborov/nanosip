#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
#   include <errno.h>
#   include <pthread.h>
#endif

#include "nanosip.h"
#include "rtp.h"

pthread_t thread_rtp_rx;
pthread_t thread_rtp_tx;

static volatile int rtp_exit = 0;

/** RTP send delay - in milliseconds */
#ifndef RTP_SEND_DELAY
#define RTP_SEND_DELAY              40
#endif

/** RTP receive timeout - in milliseconds */
#ifndef RTP_RECV_TIMEOUT
#define RTP_RECV_TIMEOUT            2000
#endif

/** RTP stats display period - in received packets */
#ifndef RTP_RECV_STATS
#define RTP_RECV_STATS              50
#endif

/** RTP macro to let the application process the data */
#ifndef RTP_RECV_PROCESSING
#define RTP_RECV_PROCESSING(p,s)
#endif

/** RTP packet/payload size */
#define RTP_PACKET_SIZE             1500
#define RTP_PAYLOAD_SIZE            1024

/** RTP header constants */
#define RTP_VERSION                 0x80
#define RTP_TIMESTAMP_INCREMENT     160
#define RTP_SSRC                    0
#define RTP_PAYLOADTYPE             96
#define RTP_MARKER_MASK             0x80
#define RFC2833_DTMF_EVENT          101

#if defined (__GNUC__)
#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_STRUCT __attribute__ ((__packed__))
#define PACK_STRUCT_END
#define PACK_STRUCT_FIELD(x) x

static struct rtp_sock {
  int sock;
  struct sockaddr_in addr;
  int rtp_port_loc;
  int rtp_port_rem;
  uint32_t ipaddr;
  ep_t *p_ep;
} _rtp_sock;

/** RTP message header */
PACK_STRUCT_BEGIN
struct rtp_hdr {
  PACK_STRUCT_FIELD(uint8_t  version);
  PACK_STRUCT_FIELD(uint8_t  payloadtype);
  PACK_STRUCT_FIELD(uint16_t seqNum);
  PACK_STRUCT_FIELD(uint32_t timestamp);
  PACK_STRUCT_FIELD(uint32_t ssrc);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END

PACK_STRUCT_BEGIN
struct rtp_dtmf_event {
    uint8_t  event;      /**< Event type ID.     */
    uint8_t  e_vol;      /**< Event volume.      */
    uint16_t duration;   /**< Event duration.    */
}PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#endif

/* RFC 2833 digit */
static const char digitmap[17] = { '0', '1', '2', '3',
                                   '4', '5', '6', '7',
                                   '8', '9', '*', '#',
                                   'A', 'B', 'C', 'D', 
                                   'R'};

static struct rtp_dtmf_stream {
    uint16_t last_dtmf_dur;
    int8_t last_dtmf;
} g_rtp_dtmf_stream;

static struct rtp_ep {
    int sockfd;
    uint8_t ip[4];
    uint16_t loc_port;
    uint16_t rem_port;
    ep_t *p_ep;
} rtp_ep;
//extern char rtp_data[];

/** RTP packets */
static uint8_t rtp_recv_packet[RTP_PACKET_SIZE];

#ifndef MIN
# define MIN(a,b) ((a>b)?b:a)
#endif

#ifndef MAX
# define MAX(a,b) ((a>b)?a:b)
#endif

void dtmf_digit_action(char digit) {
    printf("DTMF: %c\r\n", digit);
}

/*
 * Handle incoming DTMF digits.
 */
static int handle_incoming_dtmf(struct rtp_dtmf_stream *stream, void *payload, int payloadlen) {
    struct rtp_dtmf_event *event = (struct rtp_dtmf_event *)payload;

    if (payloadlen < sizeof(struct rtp_dtmf_event))
    return -1;

    /* Check if this is the same/current digit of the last packet. */
    if (stream->last_dtmf != -1 && event->event == stream->last_dtmf && 
        ntohs(event->duration) >= stream->last_dtmf_dur) {
    /* Yes, this is the same event. */
        stream->last_dtmf_dur = ntohs(event->duration);
        return -1;
    }
    //printf("Last event: %d\r\n", event->event);
    stream->last_dtmf = event->event;
    stream->last_dtmf_dur = ntohs(event->duration);

    return stream->last_dtmf;
}

/**
 * RTP send packets
 */
static void rtp_send_packets(int sock, struct sockaddr_in* to) {
    /* send RTP stream packet */
    if (sendto(sock, rtp_data, sizeof(rtp_data),
        0, (struct sockaddr *)to, sizeof(struct sockaddr)) >= 0) {
    } else {
      printf("rtp_sender: not sendto==%i\n", errno);
    }
}

/*
 *
 */
void rtp_deinit_socket(struct rtp_sock *ps) {
  close(ps->sock);
}

/*
 *
 */
int rtp_init_socket(struct rtp_ep *ep, struct rtp_sock *ps) {
  struct sockaddr_in local;
  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;

  IP4_ADDR(ps->ipaddr, ep->ip[0], ep->ip[1], ep->ip[2], ep->ip[3]);
  ps->rtp_port_loc = ep->loc_port;
  ps->rtp_port_rem = ep->rem_port;
  ps->sock = socket(AF_INET, SOCK_DGRAM, 0);
  ps->addr.sin_family      = AF_INET;
  ps->addr.sin_port        = htons(ep->loc_port);
  ps->addr.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(ps->sock, (struct sockaddr *)&ps->addr, sizeof(ps->addr)) != 0) 
    return -1;

  setsockopt(ps->sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
  return 0;
}

/**
 * RTP send thread
 */
static void *rtp_tx_thread(void *arg) {
  struct sockaddr_in to;
  struct rtp_sock *ps = (struct rtp_sock *)arg;
  struct rtp_hdr *rtphdr = (struct rtp_hdr *)rtp_data;
  uint8_t *p;

  /* initialize RTP stream address */
  if (ps->sock >= 0) {
      memset(&to, 0, sizeof(to));
      to.sin_family      = AF_INET;
      to.sin_port        = htons(ps->rtp_port_rem);
      to.sin_addr.s_addr = ps->ipaddr;

      p = rtp_data;
      p[1] = 0x88;

      rtp_send_packets(ps->sock, &to);
      rtphdr->seqNum = htons(ntohs(rtphdr->seqNum) + 1);
      rtphdr->timestamp = htonl(ntohl(rtphdr->timestamp) + RTP_TIMESTAMP_INCREMENT);

      printf("RTP Tx thread created\r\n");

      while (rtp_exit == 0) {
        rtp_send_packets(ps->sock, &to);
        rtphdr->seqNum = htons(ntohs(rtphdr->seqNum) + 1);
        rtphdr->timestamp = htonl(ntohl(rtphdr->timestamp) + RTP_TIMESTAMP_INCREMENT);
        usleep(20000);
      }
      printf("RTP Tx thread exit\r\n");
      pthread_exit(NULL);
  }
}

/**
 * RTP recv thread
 */
static void *rtp_rx_thread(void *arg) {
  struct sockaddr_in local;
  struct sockaddr_in from;
  int                fromlen;
  struct rtp_hdr*    rtphdr;
  int                result;
  int                recvrtppackets  = 0;
  int                lostrtppackets  = 0;
  uint16_t           lastrtpseq = 0;
  struct rtp_sock *ps = (struct rtp_sock *)arg;

  if (ps->sock >= 0) {
    /* prepare local address */
    memset(&local, 0, sizeof(local));
    local.sin_family      = AF_INET;
    local.sin_port        = htons(ps->rtp_port_loc);
    local.sin_addr.s_addr = htonl(INADDR_ANY);

      /* receive RTP packets */
    printf("RTP Rx thread created\r\n");

    while(rtp_exit == 0) {
      fromlen = sizeof(from);
      result  = recvfrom(ps->sock, rtp_recv_packet, sizeof(rtp_recv_packet), 0,
        (struct sockaddr *)&from, (socklen_t *)&fromlen);
      if (result >= sizeof(struct rtp_hdr)) {
        rtphdr = (struct rtp_hdr *)rtp_recv_packet;
        recvrtppackets++;
        if ((lastrtpseq == 0) || ((lastrtpseq + 1) == ntohs(rtphdr->seqNum))) {
          RTP_RECV_PROCESSING((rtp_recv_packet + sizeof(rtp_hdr)),(result-sizeof(rtp_hdr)));
        } else {
          lostrtppackets++;
        }

        lastrtpseq = ntohs(rtphdr->seqNum);

        if (rtphdr->payloadtype == RFC2833_DTMF_EVENT) {
            // DTMF data
            uint8_t *p = (uint8_t *)(rtp_recv_packet + sizeof(struct rtp_hdr));
            int digit = handle_incoming_dtmf(&g_rtp_dtmf_stream, p , 
                                             fromlen - sizeof(struct rtp_hdr));
            if (digit >= 0) {
                // action on digit
                dtmf_digit_action(digitmap[digit & 0xF]);
            }
        } else {
            // voice data
            if ((recvrtppackets % RTP_RECV_STATS) == 0) {
                printf("rtp_recv_thread: recv %6i packet(s) / lost %4i packet(s) (%.4f%%)...\n", recvrtppackets, lostrtppackets, (lostrtppackets*100.0)/recvrtppackets);
            }
        }

      } else {
        printf("rtp_recv_thread: recv timeout...\n");
      }
    }
    printf("RTP Rx thread exit\r\n");
    pthread_exit(NULL);
  }
}

int rtp_start(sipdialog_t *_dlg) {
  rtp_exit = 0;
  if (_dlg != NULL) {
        sipdialog_t *dlg = (sipdialog_t *)_dlg;
        memcpy(rtp_ep.ip, dlg->ep_rtp.ip, 4);
        rtp_ep.loc_port = dlg->local_rtp_port;
        rtp_ep.rem_port = dlg->rem_rtp_port;
        rtp_ep.p_ep = &dlg->ep_rtp;
        _rtp_sock.p_ep = &dlg->ep_rtp;
    } else {
        return -1;
    }

  rtp_init_socket(&rtp_ep, &_rtp_sock);
  pthread_create(&thread_rtp_tx, NULL, rtp_tx_thread, (void *)&_rtp_sock);
  pthread_create(&thread_rtp_rx, NULL, rtp_rx_thread, (void *)&_rtp_sock);
  return 0;
}

int rtp_stop(sipdialog_t *dlg) {
  rtp_exit = 1;
  pthread_join(thread_rtp_tx, NULL);
  pthread_join(thread_rtp_rx, NULL);
  rtp_deinit_socket(&_rtp_sock);
  return 0;
}
