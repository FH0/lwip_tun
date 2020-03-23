#include <lwip/sockets.h>
#include <lwip/tcpip.h>

err_t output(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr);

int mylwip_init() {
  tcpip_init(NULL, NULL);
  netif_list->mtu = 1500;
  netif_list->output = output;
  int tcp_sock = lwip_socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  lwip_inet_pton(AF_INET, "0.0.0.0", &addr.sin_addr);
  lwip_bind(tcp_sock, (struct sockaddr *)&addr, sizeof(addr));
  lwip_listen(tcp_sock, 512);
  return tcp_sock;
}

void tcp_thread(void *arg) {
  struct sockaddr_in addr, _addr;
  socklen_t socklen = sizeof(struct sockaddr_in);
  int connFd = lwip_accept(*(int *)arg, (struct sockaddr *)&addr, &socklen);

  lwip_getsockname(connFd, (struct sockaddr *)&_addr, &socklen);
  char sip[16], dip[16];
  lwip_inet_ntop(AF_INET, &addr.sin_addr, sip, 16);
  lwip_inet_ntop(AF_INET, &_addr.sin_addr, dip, 16);
  printf("%-20s -> %-20s \n", sip, dip);
}
