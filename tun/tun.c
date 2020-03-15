#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ipv6.h>
#include <lwip/api.h>
#include <lwip/init.h>
#include <lwip/netif.h>
#include <lwip/tcp.h>
#include <lwip/timeouts.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pthread.h>
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
    do {                                                                       \
        if (!(expr)) {                                                         \
            fprintf(stderr, "Assertion failed in %s on line %d: %s\n",         \
                    __FILE__, __LINE__, #expr);                                \
            perror("");                                                        \
            abort();                                                           \
        }                                                                      \
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
    ASSERT(-1 != (ioctl(sock6Fd, SIOCSIFADDR, &ifr6)));
    close(sock6Fd);

    /* link up */
    ifr.ifr_flags |= IFF_UP;
    ASSERT(-1 != (ioctl(sockFd, SIOCSIFFLAGS, &ifr)));
    close(sockFd);
}

err_t accept_cb(void *arg, struct tcp_pcb *new_pcb, err_t err) {
    if (err != ERR_OK)
        return err;

    char sip[16],dip[16];
    inet_ntop(AF_INET, &new_pcb->local_ip, sip, 16);
    inet_ntop(AF_INET, &new_pcb->remote_ip, dip, 16);
    printf("%-10s -> %-10s\n", sip, dip);

    /* 在这里注册回调函数，处理数据 */

    return ERR_OK;
}

err_t output(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr) {
    char buf[1500];
    u16_t bufLen = pbuf_copy_partial(p, buf, p->tot_len, 0);
    (void)(write(tunFd, buf, bufLen) + 1);
    return ERR_OK;
}

int main(int argc, char const *argv[]) {
    tun_init();

    lwip_init();
    netif_list->mtu = 1500;
    netif_list->output = output;
    struct tcp_pcb *tpcb = tcp_new();
    tcp_bind(tpcb, IP_ADDR_ANY, 0);
    tpcb = tcp_listen(tpcb);
    tcp_accept(tpcb, accept_cb);

    char *buf = malloc(1500);
    int nread;
    struct pbuf *p;

    sys_check_timeouts();
    for (;;) {
        nread = read(tunFd, buf, 1500);
        if (nread == -1 || buf[0] >> 4 != 4)
            continue;

        p = pbuf_alloc(PBUF_RAW, (u16_t)nread, PBUF_POOL);
        pbuf_take(p, buf, (u16_t)nread);
        netif_list->input(p, netif_list);

        sys_check_timeouts();
    }
    return 0;
}
