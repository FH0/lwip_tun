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
#include <sys/epoll.h>
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
static int epollFd;
typedef struct {
  struct tcp_pcb *pcb;
  struct pbuf *p;
  int fd;
} data_t;

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

int socket_send_left(int sockFd) {
  socklen_t intLen = sizeof(int);
  int sendMax, sendUsed;
  getsockopt(sockFd, SOL_SOCKET, SO_SNDBUF, &sendMax, &intLen);
  sendMax = sendMax / 2; /* linux cause this */
  ioctl(sockFd, SIOCOUTQ, &sendUsed);
  return sendMax - sendUsed;
}

int socket_recv_used(int sockFd) {
  int recvUsed;
  ioctl(sockFd, SIOCINQ, &recvUsed);
  return recvUsed;
}

int tcp_status(int sockFd) {
  struct tcp_info info;
  socklen_t len = sizeof(info);
  getsockopt(sockFd, IPPROTO_TCP, TCP_INFO, &info, &len);
  return info.tcpi_state;
}

void epoll_add_fd(void *ptr) {
  struct epoll_event event;
  data_t *data = ptr;
  event.data.ptr = ptr;
  event.events = EPOLLIN | EPOLLOUT | EPOLLET;
  epoll_ctl(epollFd, EPOLL_CTL_ADD, data->fd, &event);
  ASSERT(-1 != fcntl(data->fd, F_SETFL, fcntl(data->fd, F_GETFL) | O_NONBLOCK));
}

err_t tcp_raw_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
  ASSERT(arg != NULL);
  data_t *data = (data_t *)arg;
  int status = tcp_status(data->fd);

  if (data->p == NULL)
    data->p = p;

  if (p == NULL) {
    if (status == 8) { /* CLOSE_WAIT */
      tcp_close(tpcb);
      close(data->fd);
      free(data);
    } else {
      shutdown(data->fd, 1);
    }
    return ERR_OK;
  }

  if (status == 2) /* SYN_SENT */
    return ERR_OK;

  int left = socket_send_left(data->fd);
  if (p->tot_len <= left) {
    char buf[p->tot_len];
    int n = pbuf_copy_partial(p, buf, p->tot_len, 0);
    printf("p->tot_len %d n %d\n", p->tot_len, n);
    tcp_recved(tpcb, n);
    (void)(write(data->fd, buf, p->tot_len) + 1);
  } else { /* make it EAGAIN */
    char buf[left + 1];
    tcp_recved(tpcb, pbuf_copy_partial(p, buf, left, 0));
    (void)(write(data->fd, buf, left + 1) + 1);
  }

  return ERR_OK;
}

err_t tcp_raw_sent(void *arg, struct tcp_pcb *tpcb, u16_t len) {
  ASSERT(arg != NULL);
  data_t *data = (data_t *)arg;

  int used = socket_recv_used(data->fd);
  if (used > 0) {
    int bufLen = (used <= tpcb->snd_buf) ? used : tpcb->snd_buf;
    char buf[bufLen];
    (void)(read(data->fd, buf, bufLen) + 1);
    tcp_write(tpcb, buf, bufLen, TCP_WRITE_FLAG_COPY);
    tcp_output(tpcb);
  }

  return ERR_OK;
}

void tcp_raw_error(void *arg, err_t err) {
  data_t *data = (data_t *)arg;
  close(data->fd);
  free(data);
}

err_t accept_cb(void *arg, struct tcp_pcb *new_pcb, err_t err) {
  if (err != ERR_OK || new_pcb == NULL)
    return err;

  // char sip[16], dip[16];
  // inet_ntop(AF_INET, &new_pcb->local_ip, sip, 16);
  // inet_ntop(AF_INET, &new_pcb->remote_ip, dip, 16);
  // printf("%-10s -> %-10s\n", sip, dip);

  new_pcb->flags |= TF_ACK_NOW | TF_NODELAY;

  data_t *data = malloc(sizeof(data_t));
  ASSERT(data != NULL);
  data->pcb = new_pcb;
  data->p = NULL;

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  memcpy(&addr.sin_addr.s_addr, &new_pcb->local_ip, 4);
  addr.sin_port = htons(new_pcb->local_port);

  data->fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT(-1 != data->fd);
  epoll_add_fd(data);

  if (connect(data->fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    ASSERT(errno == EINPROGRESS);

  tcp_arg(new_pcb, data);
  tcp_recv(new_pcb, tcp_raw_recv);
  tcp_err(new_pcb, tcp_raw_error);
  tcp_sent(new_pcb, tcp_raw_sent);

  return ERR_OK;
}

err_t output(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr) {
  char buf[1500];
  u16_t bufLen = pbuf_copy_partial(p, buf, p->tot_len, 0);
  (void)(write(tunFd, buf, bufLen) + 1);
  return ERR_OK;
}

int main(int argc, char const *argv[]) {
  signal(SIGPIPE, SIG_IGN);

  epollFd = epoll_create1(EPOLL_CLOEXEC);

  tun_init();
  struct epoll_event event;
  data_t *data = malloc(sizeof(data_t));
  data->fd = tunFd;
  event.data.ptr = data;
  event.events = EPOLLIN | EPOLLOUT | EPOLLET;
  epoll_ctl(epollFd, EPOLL_CTL_ADD, data->fd, &event);
  ASSERT(-1 != fcntl(data->fd, F_SETFL, fcntl(data->fd, F_GETFL) | O_NONBLOCK));

  lwip_init();
  netif_list->mtu = 1500;
  netif_list->output = output;
  struct tcp_pcb *tpcb = tcp_new();
  tcp_bind(tpcb, IP_ADDR_ANY, 0);
  tpcb = tcp_listen(tpcb);
  tcp_accept(tpcb, accept_cb);
  sys_check_timeouts();

  char *buf = malloc(1500);
  int nread;
  struct pbuf *pbuf;

  int n;
loop:;
  struct epoll_event events[512];
  n = epoll_wait(epollFd, events, 512, -1);
  ASSERT(n != -1);

  for (int i = 0; i < n; i++) {
    data_t *data = (data_t *)events[i].data.ptr;
    struct pbuf *p = data->p;
    struct tcp_pcb *tpcb = data->pcb;

    if (data->fd == tunFd) {
      nread = read(tunFd, buf, 1500);
      if (nread == -1 || buf[0] >> 4 != 4 || buf[9] != 6)
        continue;

      pbuf = pbuf_alloc(PBUF_RAW, (u16_t)nread, PBUF_POOL);
      ASSERT(pbuf != NULL);
      ASSERT(pbuf_take(pbuf, buf, (u16_t)nread) == ERR_OK);
      ASSERT(netif_list->input(pbuf, netif_list) == ERR_OK);
      // sys_check_timeouts();
    } else if (events[i].events & EPOLLIN) {
      int used = socket_recv_used(data->fd);
      if (used == 0) {
        char tmp;
        if (read(data->fd, &tmp, 1) == 0 && tpcb->state != CLOSE_WAIT) {
          tcp_shutdown(tpcb, 0, 1);
        } else {
          tcp_close(tpcb);
          close(data->fd);
          free(data);
        }
      } else {
        int bufLen = (used <= tpcb->snd_buf) ? used : tpcb->snd_buf;
        char buf[bufLen];
        (void)(read(data->fd, buf, bufLen) + 1);
        tcp_write(tpcb, buf, bufLen, TCP_WRITE_FLAG_COPY);
        tcp_output(tpcb);
      }
    } else if (events[i].events & EPOLLOUT) {
      if (p == NULL)
        continue;

      int left = socket_send_left(data->fd);
      if (p->tot_len <= left) {
        char buf[p->tot_len];
        int a = pbuf_copy_partial(p, buf, p->tot_len, 0);
        tcp_recved(tpcb, a);
        (void)(write(data->fd, buf, p->tot_len) + 1);
      } else { /* make it EAGAIN */
        char buf[left + 1];
        tcp_recved(tpcb, pbuf_copy_partial(p, buf, left, 0));
        (void)(write(data->fd, buf, left + 1) + 1);
      }
    } else {
      puts("epoll unknown event");
    }
  }
  goto loop;

  return 0;
}
