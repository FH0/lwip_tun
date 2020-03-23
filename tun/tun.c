#include "additional.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ipv6.h>
#include <linux/sockios.h>
#include <lwip/api.h>
#include <lwip/init.h>
#include <lwip/netif.h>
#include <lwip/tcp.h>
#include <lwip/tcpip.h>
#include <lwip/timeouts.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define ASSERT(expr)                                                           \
  do {                                                                         \
    if (!(expr)) {                                                             \
      fprintf(stderr, "Assertion failed in %s on line %d: %s\n", __FILE__,     \
              __LINE__, #expr);                                                \
      perror("");                                                              \
      abort();                                                                 \
    }                                                                          \
  } while (0)

static int tunFd;

/* create tun device */
void tun_init() {
  struct ifreq ifr;

  tunFd = open("/dev/net/tun", O_RDWR);
  ASSERT(-1 != tunFd);

  /* set name */
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy(ifr.ifr_name, "tun3", IFNAMSIZ);
  ASSERT(-1 != (ioctl(tunFd, TUNSETIFF, &ifr)));

  /* set mtu */
  int sockFd = socket(AF_INET, SOCK_DGRAM, 0);
  ASSERT(-1 != sockFd);
  ifr.ifr_mtu = 1500;
  ASSERT(-1 != (ioctl(sockFd, SIOCSIFMTU, &ifr)));

  /* add ipv4 address */
  struct sockaddr_in sai;
  memset(&sai, 0, sizeof(struct sockaddr_in));
  sai.sin_family = AF_INET;
  inet_pton(AF_INET, "10.5.5.5", &sai.sin_addr.s_addr);
  memcpy(&ifr.ifr_addr, &sai, sizeof(struct sockaddr_in));
  ASSERT(-1 != (ioctl(sockFd, SIOCSIFADDR, &ifr)));

  /* add ipv6 address */
  int sock6Fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);
  ASSERT(-1 != sock6Fd);
  ASSERT(-1 != (ioctl(sock6Fd, SIOGIFINDEX, &ifr)));
  struct in6_ifreq ifr6;
  inet_pton(AF_INET6, "fd00::5", &ifr6.ifr6_addr);
  ifr6.ifr6_prefixlen = 64;
  ifr6.ifr6_ifindex = ifr.ifr_ifindex;
  ioctl(sock6Fd, SIOCSIFADDR, &ifr6); /* ASSERT no need,
                                       * ipv6 may denied*/
  close(sock6Fd);

  /* link up */
  ifr.ifr_flags |= IFF_UP;
  ASSERT(-1 != (ioctl(sockFd, SIOCSIFFLAGS, &ifr)));
  close(sockFd);
}

err_t output(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr) {
  char buf[1500];
  u16_t bufLen = pbuf_copy_partial(p, buf, p->tot_len, 0);
  (void)(write(tunFd, buf, bufLen) + 1);
  return ERR_OK;
}

void tun_thread(void *arg) {
  char *buf = malloc(1500);
  int nread;
  struct pbuf *pbuf;

  for (;;) {
    nread = read(tunFd, buf, 1500);
    if (nread == -1 || buf[0] >> 4 != 4 || buf[9] != 6)
      continue;

    pbuf = pbuf_alloc(PBUF_RAW, (u16_t)nread, PBUF_POOL);
    ASSERT(pbuf != NULL);
    ASSERT(pbuf_take(pbuf, buf, (u16_t)nread) == ERR_OK);
    ASSERT(netif_list->input(pbuf, netif_list) == ERR_OK);
  }
}

int main(int argc, char const *argv[]) {
  signal(SIGPIPE, SIG_IGN);

  tun_init();

  int tcp_sock = mylwip_init();

  sys_thread_new("tun", (void *)&tun_thread, NULL, DEFAULT_THREAD_STACKSIZE,
                 DEFAULT_THREAD_PRIO);
  sys_thread_new("tcp", (void *)&tcp_thread, &tcp_sock,
                 DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);

  pause();
  return 0;
}
