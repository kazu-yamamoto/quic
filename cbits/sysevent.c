/* watch_socket: 0 for an event, -1 to try again (EINTR), -2 to give up. */
#if defined(OS_MacOS)
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/kern_event.h>

int open_socket () {
   struct kev_request filter = { 0 };

   int s = socket(PF_SYSTEM, SOCK_RAW, SYSPROTO_EVENT);
   if (s < 0) return -1;

   filter.vendor_code = KEV_VENDOR_APPLE;
   filter.kev_class = KEV_NETWORK_CLASS;
   filter.kev_subclass = KEV_DL_SUBCLASS;
   if (ioctl(s, SIOCSKEVFILT, &filter) < 0) {
     close(s);
     return -1;
   }

   return s;
}

int watch_socket(int s) {
   struct kern_event_msg msg;
   int ret = recv(s, &msg, sizeof(msg), 0);
   if (ret < 0) {
     return errno == EINTR ? -1 : -2;
   } else {
     return 0;
   }
}

int close_socket (int s) {
  int ret = close(s);
  return ret;
}
#elif defined(OS_Linux)
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

int open_socket () {
  struct sockaddr_nl filter = { 0 };

  int s = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (s < 0) return -1;

  filter.nl_family = AF_NETLINK;
  filter.nl_groups = RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;
  if (bind(s, (struct sockaddr *)&filter, sizeof(filter)) < 0) {
    close(s);
    return -1;
  }

  return s;
}

int watch_socket(int s) {
  char msg[4096] = {0};
  int ret = recv(s, msg, sizeof(msg), 0);
   if (ret < 0) {
     return errno == EINTR ? -1 : -2;
   } else {
     return 0;
   }
}

int close_socket (int s) {
  int ret = close(s);
  return ret;
}
#else
int open_socket () { return -1; }

int watch_socket(int s) { return -2; }

int close_socket (int s) { return 0; }
#endif
