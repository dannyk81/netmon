#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <memory.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include "common.h"

// little helper to parsing message using netlink macroses
void parseRtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));

    while (RTA_OK(rta, len)) {  // while not end of the message
        if (rta->rta_type <= max) {
            tb[rta->rta_type] = rta; // read attr
        }
        rta = RTA_NEXT(rta,len);    // get next attr
    }
}

unsigned createMask(unsigned a, unsigned b)
{
   unsigned r = 0;
   for (unsigned i=a; i<=b; i++)
       r |= 1 << i;

   return r;
}

// Returns the local date/time formatted as 2014-03-19 11:11:52
char* getFormattedTime(void) {

    time_t rawtime;
    struct tm* timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    // Must be static, otherwise won't work
    static char _retval[20];
    strftime(_retval, sizeof(_retval), "%Y-%m-%d %H:%M:%S", timeinfo);

    return _retval;
}

int main()
{
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);   // create netlink socket

    if (fd < 0) {
        LOGERROR("Failed to create netlink socket: %s", (char*)strerror(errno));
        return 1;
    }

    struct sockaddr_nl  local;  // local addr struct
    char buf[8192];             // message buffer
    struct iovec iov;           // message structure
    iov.iov_base = buf;         // set message buffer as io
    iov.iov_len = sizeof(buf);  // set size

    memset(&local, 0, sizeof(local));

    local.nl_family = AF_NETLINK;       // set protocol family
    local.nl_groups =   RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;   // set groups we interested in
    local.nl_pid = getpid();    // set out id using current process id

    // initialize protocol message header
    struct msghdr msg;  
    {
        msg.msg_name = &local;                  // local address
        msg.msg_namelen = sizeof(local);        // address size
        msg.msg_iov = &iov;                     // io vector
        msg.msg_iovlen = 1;                     // io size
    }   

    if (bind(fd, (struct sockaddr*)&local, sizeof(local)) < 0) {     // bind socket
        LOGERROR("Failed to bind netlink socket: %s", (char*)strerror(errno));
        close(fd);
        return 1;
    }   

    // read and parse all messages from the
    while (1) {
        ssize_t status = recvmsg(fd, &msg, MSG_DONTWAIT);

        //  check status
        if (status < 0) {
            if (errno == EINTR || errno == EAGAIN)
            {
                usleep(250000);
                continue;
            }

            LOGERROR("Failed to read netlink: %s", (char*)strerror(errno));
            continue;
        }

        if (msg.msg_namelen != sizeof(local)) { // check message length, just in case
            LOGERROR("Invalid length of the sender address struct");
            continue;
        }

        // message parser
        struct nlmsghdr *h;

        for (h = (struct nlmsghdr*)buf; status >= (ssize_t)sizeof(*h); ) {   // read all messagess headers
            int len = h->nlmsg_len;
            unsigned r = createMask(0,21);
            unsigned pid = r & h->nlmsg_pid;
            int l = len - sizeof(*h);
            char *ifName;

            if ((l < 0) || (len > status)) {
                LOGERROR("Invalid message length: %i", len);
                continue;
            }

            // now we can check message type
            if ((h->nlmsg_type == RTM_NEWROUTE) || (h->nlmsg_type == RTM_DELROUTE)) { // some changes in routing table
                LOGINFO("Routing table was changed");  
                switch (h->nlmsg_type) { // what is actually happenned?
                    case RTM_NEWROUTE:
                        LOGINFO("New route added by PID=%u", pid);
                        break;

                    case RTM_DELROUTE:
                        LOGINFO("Route deleted by PID=%u", pid);
                        break;
                }
            } else {    // in other case we need to go deeper
                char *ifUpp;
                char *ifRunn;
                struct ifinfomsg *ifi;  // structure for network interface info
                struct rtattr *tb[IFLA_MAX + 1];

                ifi = (struct ifinfomsg*) NLMSG_DATA(h);    // get information about changed network interface

                parseRtattr(tb, IFLA_MAX, IFLA_RTA(ifi), h->nlmsg_len);  // get attributes
                
                if (tb[IFLA_IFNAME]) {  // validation
                    ifName = (char*)RTA_DATA(tb[IFLA_IFNAME]); // get network interface name
                }

                if (ifi->ifi_flags & IFF_UP) { // get UP flag of the network interface
                    ifUpp = (char*)"UP";
                } else {
                    ifUpp = (char*)"DOWN";
                }

                if (ifi->ifi_flags & IFF_RUNNING) { // get RUNNING flag of the network interface
                    ifRunn = (char*)"RUNNING";
                } else {
                    ifRunn = (char*)"NOT RUNNING";
                }

                char ifAddress[256];    // network addr
                struct ifaddrmsg *ifa; // structure for network interface data
                struct rtattr *tba[IFA_MAX+1];

                ifa = (struct ifaddrmsg*)NLMSG_DATA(h); // get data from the network interface

                parseRtattr(tba, IFA_MAX, IFA_RTA(ifa), h->nlmsg_len);

                if (tba[IFA_LOCAL]) {
                    inet_ntop(AF_INET, RTA_DATA(tba[IFA_LOCAL]), ifAddress, sizeof(ifAddress)); // get IP addr
                }

                switch (h->nlmsg_type) { // what is actually happenned?
                    case RTM_DELADDR:
                        LOGINFO("Interface %s: address was removed", ifName);
                        break;

                    case RTM_DELLINK:
                        LOGINFO("Network interface %s was removed", ifName);
                        break;

                    case RTM_NEWLINK:
                        LOGINFO("New network interface %s, state: %s %s", ifName, ifUpp, ifRunn);
                        break;

                    case RTM_NEWADDR:
                        LOGINFO("Interface %s: new address was assigned: %s", ifName, ifAddress);
                        break;
                }
            }

            status -= NLMSG_ALIGN(len); // align offsets by the message length, this is important

            h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));    // get next message
        }

        usleep(250000); // sleep for a while
    }

    close(fd);  // close socket

    return 0;
}
