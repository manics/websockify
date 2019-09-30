/*
 * rebind: Intercept bind calls and bind to a different port
 * Copyright 2010 Joel Martin
 * Licensed under LGPL version 3 (see docs/LICENSE.LGPL-3)
 *
 * Overload (LD_PRELOAD) bind system call. If REBIND_PORT_OLD and
 * REBIND_PORT_NEW environment variables are set then bind on the new
 * port (of localhost) instead of the old port. 
 *
 * This allows a bridge/proxy (such as websockify) to run on the old port and
 * translate traffic to/from the new port.
 *
 * Usage:
 *     LD_PRELOAD=./rebind.so \
 *     REBIND_PORT_OLD=23 \
 *     REBIND_PORT_NEW=2023 \
 *     program
 */

//#define DO_DEBUG 1

#include <stdio.h>
#include <stdlib.h>

#define __USE_GNU 1  // Pull in RTLD_NEXT
#include <dlfcn.h>

#include <string.h>
#include <netinet/in.h>


#if defined(DO_DEBUG)
#define DEBUG(...) \
    fprintf(stderr, "rebind: "); \
    fprintf(stderr, __VA_ARGS__);
#else
#define DEBUG(...)
#endif


int _real_bind(void * (*func)(), int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    /* Just pass everything right through to the real bind */
    int ret = (long) func(sockfd, addr, addrlen);
    DEBUG("<< bind(%d, _, %d) ret %d\n", sockfd, addrlen, ret);
    return ret;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    static void * (*func)();
    if (!func) func = (void *(*)()) dlsym(RTLD_NEXT, "bind");
    int do_move = 0;
    int ret;

    if (addr->sa_family == AF_INET) {
        struct sockaddr_in * addr_in = (struct sockaddr_in *)addr;
        struct sockaddr_in addr_tmp;
        addr_in = (struct sockaddr_in *)addr;
        char * PORT_OLD, * PORT_NEW, * end1, * end2;
        socklen_t addrlen_tmp;
        int oldport, newport, askport = htons(addr_in->sin_port);
        uint32_t askaddr = htons(addr_in->sin_addr.s_addr);

        DEBUG(">> bind(%d, _, %d), askaddr %d, askport %d [ipv4]\n",
            sockfd, addrlen, askaddr, askport);

        PORT_OLD = getenv("REBIND_OLD_PORT");
        PORT_NEW = getenv("REBIND_NEW_PORT");
        if (PORT_OLD && (*PORT_OLD != '\0') &&
            PORT_NEW && (*PORT_NEW != '\0')) {
            oldport = strtol(PORT_OLD, &end1, 10);
            newport = strtol(PORT_NEW, &end2, 10);
            if (oldport && (*end1 == '\0') &&
                newport && (*end2 == '\0') &&
                (oldport == askport)) {
                do_move = 1;
            }
        }

        if (! do_move) {
            return _real_bind(func, sockfd, addr, addrlen);
        }

        DEBUG("binding fd %d on localhost:%d instead of 0x%x:%d\n",
            sockfd, newport, ntohl(addr_in->sin_addr.s_addr), oldport);

        /* Use a temporary location for the new address information */
        addrlen_tmp = sizeof(addr_tmp);
        memcpy(&addr_tmp, addr, addrlen_tmp);

        /* Bind to other port on the loopback instead */
        addr_tmp.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr_tmp.sin_port = htons(newport);
        ret = (long) func(sockfd, &addr_tmp, addrlen_tmp);
    }

    // http://www.beej.us/guide/bgnet/html/multi/sockaddr_inman.html
    if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 * addr_in6 = (struct sockaddr_in6 *)addr;
        struct sockaddr_in6 addr_tmp6;
        addr_in6 = (struct sockaddr_in6 *)addr;
        char * PORT_OLD, * PORT_NEW, * end1, * end2;
        socklen_t addrlen_tmp;
        int oldport, newport, askport = htons(addr_in6->sin6_port);
        unsigned char *askaddr = addr_in6->sin6_addr.s6_addr;

        DEBUG(">> bind(%d, _, %d), askaddr %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x, askport %d [ipv6]\n",
            sockfd, addrlen,
            askaddr[0], askaddr[1], askaddr[2], askaddr[3],
            askaddr[4], askaddr[5], askaddr[6], askaddr[7],
            askaddr[8], askaddr[9], askaddr[10], askaddr[11],
            askaddr[12], askaddr[13], askaddr[14], askaddr[15],
            askport);

        PORT_OLD = getenv("REBIND_OLD_PORT");
        PORT_NEW = getenv("REBIND_NEW_PORT");
        if (PORT_OLD && (*PORT_OLD != '\0') &&
            PORT_NEW && (*PORT_NEW != '\0')) {
            oldport = strtol(PORT_OLD, &end1, 10);
            newport = strtol(PORT_NEW, &end2, 10);
            if (oldport && (*end1 == '\0') &&
                newport && (*end2 == '\0') &&
                (oldport == askport)) {
                do_move = 1;
            }
        }

        if (! do_move) {
            return _real_bind(func, sockfd, addr, addrlen);
        }

        unsigned char *origaddr = addr_in6->sin6_addr.s6_addr;
        DEBUG("binding fd %d on localhost:%d instead of %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%d\n",
            sockfd, newport,
            origaddr[0], origaddr[1], origaddr[2], origaddr[3],
            origaddr[4], origaddr[5], origaddr[6], origaddr[7],
            origaddr[8], origaddr[9], origaddr[10], origaddr[11],
            origaddr[12], origaddr[13], origaddr[14], origaddr[15],
            oldport);

        /* Use a temporary location for the new address information */
        addrlen_tmp = sizeof(addr_tmp6);
        memcpy(&addr_tmp6, addr, addrlen_tmp);

        /* Bind to other port on the loopback instead */
        addr_tmp6.sin6_addr = in6addr_loopback;
        addr_tmp6.sin6_port = htons(newport);
        ret = (long) func(sockfd, &addr_tmp6, addrlen_tmp);
    }

    DEBUG("<< bind(%d, _, %d) ret %d\n", sockfd, addrlen, ret);
    return ret;
}
