/*
 * isatapd.c - ISATAP Router and Prefix Discovery [RFC5214]
 */

/*************************************************************************
 *  Copyright © 2004-2006 Rémi Denis-Courmont.                         *
 *  This program is free software: you can redistribute and/or modify    *
 *  it under the terms of the GNU General Public License as published by *
 *  the Free Software Foundation, versions 2 or 3 of the license.        *
 *                                                                       *
 *  This program is distributed in the hope that it will be useful,      *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of       *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        *
 *  GNU General Public License for more details.                         *
 *                                                                       *
 *  You should have received a copy of the GNU General Public License    *
 *  along with this program. If not, see <http://www.gnu.org/licenses/>. *
 *************************************************************************/

/*************************************************************************
 * ISATAP Router Discovery [RFC5214]					 *
 * (c)2008-2009 the Boeing Company.					 *
 *									 *
 * Kwong-Sang Yin <kwong-sang.yin@boeing.com>				 *
 * Fred Templin <fred.l.templin@boeing.com>				 *
 *									 *
 * isatapd.c - v0.3 (24/Jul/09)						 *
 *									 *
 * This program is a modified version of ndisc.c from the                *
 * 'ndisc6-0.9.8' distribution. It implements the ISATAP IPv6            *
 * Router and Prefix Discovery procedures specfied in Section 8.3        *
 * of [RFC5214].                                                         *
 *                                                                       *
 * 'isatapd' uses a Potential Router List (PRL) to discover the          *
 * IPv4 addresses of candidate default routers available on the		 *
 * ISATAP 'link'. This program is for use on ISATAP hosts and		 *
 * non-default routers; it sends Router Solicitation (RS)		 *
 * messages over the ISATAP interface to elicit Router			 *
 * Advertisements (RAs) from default routers.				 *
 *************************************************************************/


#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <signal.h>

#include <gettext.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h> /* div() */
#include <inttypes.h>
#include <limits.h> /* UINT_MAX */
#include <locale.h>
#include <stdbool.h>
#include <errno.h> /* EMFILE */
#include <sys/types.h>
#include <unistd.h> /* close() */
#include <time.h> /* clock_gettime() */
#include <poll.h> /* poll() */
#include <sys/socket.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <sys/wait.h>
#include "gettime.h"

#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif

#include <netdb.h> /* getaddrinfo(), struct hostent */
#include <arpa/inet.h> /* inet_ntop() */
#include <net/if.h> /* if_nametoindex() */

#include <netinet/in.h>
#include <netinet/icmp6.h>

/* contains Protocol Constants for host and Node (RFCs 4861, 5214) */
#include <isatapd.h>

#ifndef IPV6_RECVHOPLIMIT
/* Using obsolete RFC 2292 instead of RFC 3542 */
# define IPV6_RECVHOPLIMIT IPV6_HOPLIMIT
#endif

#ifndef AI_IDN
# define AI_IDN 0
#endif

//TODO: Update to make use of syslog instead of text file
static FILE *debug_file;

unsigned isflags = IS_VERBOSE1;

/* prl_head points to the head of the Potential Router List PRL */
/* The PRL elements (router) are in ascending of when RSs will*/
/* be sent */
static struct prl_element *prl_head = NULL;

/* set the timer for the first element in PRL*/
int set_timer(timer_t timer_id)
{
	struct itimerspec its;

	/* set timer for the head of PRL */
	if (prl_head -> timer_set == 0)
	{
		prl_head->timer_set = 1;

		its.it_interval.tv_sec = 0;
		its.it_interval.tv_nsec = 0;
		its.it_value.tv_sec = prl_head->alarm.tv_sec;
		its.it_value.tv_nsec = prl_head->alarm.tv_nsec;
		if (timer_settime(timer_id, TIMER_ABSTIME, &its, NULL) == -1)
		{
			return -1;
		}
		else
		{
			if ((isflags & IS_VERBOSE) > IS_VERBOSE1)
			{
				printf("[DEBUG set_timer] timer set ");
				printf("to fire at %ld secs %ld nsecs\n",
					its.it_value.tv_sec,
					its.it_value.tv_nsec);
				timer_gettime(timer_id,&its);
				printf("[DEBUG set_timer] timer will ");
				printf("fire in %ld secs %ld nsecs\n",
					its.it_value.tv_sec,
					its.it_value.tv_nsec);
			}
			return 0;
		}
	}
}

/*
 * Insert ins_prl_el in ascending order into the list pointed to by
 * prl_head.
 */
int insert_prl(struct timespec firein,
	       struct prl_element *ins_prl_el)
{
	struct prl_element *curr_el;
	struct prl_element *prev_el;
	struct timespec curr_time;

	clock_gettime(CLOCK_REALTIME, &curr_time);

	/* determine when the timer should go off*/
	ins_prl_el->alarm.tv_sec = curr_time.tv_sec + firein.tv_sec;
	ins_prl_el->alarm.tv_nsec = curr_time.tv_nsec + firein.tv_nsec;
	if (ins_prl_el->alarm.tv_nsec > 1000000000)
	{
		ins_prl_el->alarm.tv_sec = ins_prl_el->alarm.tv_sec + 1;
		ins_prl_el->alarm.tv_nsec = ins_prl_el->alarm.tv_nsec - 1000000000;
	}

        if ((isflags & IS_VERBOSE) > IS_VERBOSE1)
        {
		printf("[DEBUG insert_prl pid %i] ",getpid());
                printf("current time %ld secs %ld nsecs\n", curr_time.tv_sec,
                        curr_time.tv_nsec);
                if (prl_head != NULL)
                        printf("[DEBUG insert_prl] current timer to fire at %ld secs %ld nsecs\n",
                                prl_head->alarm.tv_sec, prl_head->alarm.tv_nsec);

                printf("[DEBUG insert_prl] new prl element fire at %ld secs %ld nsecs\n",
                	ins_prl_el->alarm.tv_sec, ins_prl_el->alarm.tv_nsec);
	}

	/* The PRL is in ascending order, insert the prl_el into the PRL */
	/* After inserting prl_el in the prl, reset timer if necessary*/
	if (prl_head == NULL)
	{
		/*Insert first element into PRL */
		prl_head = ins_prl_el;
		prl_head->timer_set = 0;
	        if ((isflags & IS_VERBOSE) > IS_VERBOSE2)
			printf("[DEBUG insert_prl] created PRL with"
	  			" 1 element\n");
	}
	else
	{
		prev_el = NULL;
		curr_el = prl_head;
		while ((curr_el->next != NULL) &&
			((ins_prl_el->alarm.tv_sec > curr_el->alarm.tv_sec) ||
			((ins_prl_el->alarm.tv_sec == curr_el->alarm.tv_sec) &&
			 (ins_prl_el->alarm.tv_nsec > curr_el->alarm.tv_nsec))))
		{
			prev_el = curr_el;
			curr_el = curr_el->next;
		}

		/* insert into the PRL*/
                if ((ins_prl_el->alarm.tv_sec < curr_el->alarm.tv_sec) ||
                    ((ins_prl_el->alarm.tv_sec == curr_el->alarm.tv_sec) &&
                     (ins_prl_el->alarm.tv_nsec < curr_el->alarm.tv_nsec)))
		{
			/* insert ahead of current element*/
			ins_prl_el->next = curr_el;
			ins_prl_el->prev = curr_el->prev;
			curr_el->prev = ins_prl_el;

			if (curr_el == prl_head)
			{
	                        /* inserting at head of list but also set */
	                        /* the previous timer off  */
				curr_el->timer_set = 0;
				prl_head = ins_prl_el;
                                prl_head->timer_set = 0;
                                if ((isflags & IS_VERBOSE) > IS_VERBOSE2)
                        		printf("[DEBUG insert_prl] inserted at "
                        			"head of PRL\n");
			}
			else
			{
                                /* insert into the body of the prl */
				prev_el->next = ins_prl_el;
                                if ((isflags & IS_VERBOSE) > IS_VERBOSE2)
                        		printf("[DEBUG insert_prl] inserted in "
                        			"body of PRL\n");
			}
		}
		else
		{
			/* insert at the tail of prl*/
			curr_el->next = ins_prl_el;
			ins_prl_el->prev = curr_el;
			ins_prl_el->next = NULL;
                        if ((isflags & IS_VERBOSE) > IS_VERBOSE2)
                        	printf("[DEBUG insert_prl] inserted at "
                        		"end of PRL\n");
		}
	}

	return 0;
}


/*** signal handling */
struct sigaction        signal_action; /* for SIG_TIMER*/
timer_t                 timer_id;

void
sigkill_handler(int sig)
{
	/* handle POSIX signal SIGKILL */
	if ((isflags & IS_VERBOSE) > IS_VERBOSE1)
	{
		printf("[DEBUG sigkill_handler] called\n");
		printf("child process pid %i\n",
			getpid());
	}
	timer_delete(timer_id);
	raise(SIGKILL);
}



static int
getipv6byname (const char *name, const char *ifname, int numeric,
               struct sockaddr_in6 *addr)
{
	int decimal_octet[4];
	int i;
	char *ipv4octet;
	char hex[3];

	char *wrk_ptr;
	char *ipv4name;
	char ipv6name[46];

	if ((isflags & IS_VERBOSE) > IS_VERBOSE2)
	{
		printf("[DEBUG getipv6byname] call with name %s ",
			name);
		printf("ifname %s\n", ifname);
	}

	/* convert from ipv4 to ipv6 name*/
	ipv4name = (char *) malloc(16*sizeof(char)); /* 255.255.255.255 */

	/* start off assuming "universal" */
	strcpy(ipv6name,"fe80:0000:0000:0000:0200:5efe");

	/* change from decimal octet to hexidecimal notation */
	i = 0;
	strcpy(ipv4name,name);
	ipv4octet = strtok_r(ipv4name, ".", &wrk_ptr);
	while (ipv4octet != NULL)
	{
		decimal_octet[i] = atoi(ipv4octet);
		sprintf(hex,"%02x",decimal_octet[i]);/* 2 char hexadecimal */

		if ((i%2) == 0)
		{
			strcat(ipv6name,":");
		}
		i++;
		strcat(ipv6name,hex);
		/* get the next octet */
		ipv4octet = strtok_r(NULL, ".", &wrk_ptr);
	}
	free(ipv4name);

	i = 0;
	/* check for special use addresses (RFC3330) */
	switch (decimal_octet[0]) {
	case 0:
	case 10:
	case 14:
	case 24:
	case 39:
	case 127:
		i++;
		break;
	case 128:
		if (decimal_octet[1] == 0)
			i++;
		break;
	case 169:
		if (decimal_octet[1] == 254)
			i++;
		break;
	case 172:
		if ((decimal_octet[1] >= 16) && (decimal_octet[1] <= 31))
			i++;
		break;
	case 191:
		if (decimal_octet[1] == 255)
			i++;
		break;
	case 192:
		switch (decimal_octet[1]) {
		case 0:
			if ((decimal_octet[2] == 0)||(decimal_octet[2] == 2))
				i++;
			break;
		case 88:
			if (decimal_octet[2] == 99)
				i++;
			break;
		case 168:
			i++;
		default:
			break;
		}
		break;
	case 198:
		if ((decimal_octet[1] == 18) || (decimal_octet[1] == 19))
			i++;
		break;
	case 223:
		if ((decimal_octet[1] == 255) && (decimal_octet[2] == 255))
			i++;
	default:
		break;
	}

	/* clear the "universal" bit, if necessary */
	if (i)
		ipv6name[21] = '0';

	if ((isflags & IS_VERBOSE) > IS_VERBOSE2)
	{
		printf("[DEBUG getipv6byname] ipv6: %s\n",
			ipv6name);
	}

	struct addrinfo hints, *res;
	memset (&hints, 0, sizeof (hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM; /* dummy */
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;

	int val = getaddrinfo (ipv6name, NULL, &hints, &res);
	if (val)
	{
		fprintf (stderr, _("%s: %s\n"), ipv6name, gai_strerror (val));
		return -1;
	}

	memcpy (addr, res->ai_addr, sizeof (struct sockaddr_in6));
	freeaddrinfo (res);

	val = if_nametoindex (ifname);
	if (val == 0)
	{
		perror (ifname);
		return -1;
	}
	addr->sin6_scope_id = val;

	return 0;
}


static inline int
setmcasthoplimit (int fd, int value)
{
	return setsockopt (fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
	                   &value, sizeof (value));
}

static inline int
setucasthoplimit (int fd, int value)
{
	return setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
			  &value, sizeof(value));
}

static void
printmacaddress (const uint8_t *ptr, size_t len)
{
	while (len > 1)
	{
		printf ("%02X:", *ptr);
		ptr++;
		len--;
	}

	if (len == 1)
		printf ("%02X\n", *ptr);
}



static const uint8_t nd_type_advert = ND_ROUTER_ADVERT;
static const unsigned nd_delay_ms = RTR_SOLICITATION_INTERVAL * 1000;
static const char isatapd_usage[] = N_(
	"Usage: %s [options]... [addrs]...\n"
	"ISATAP Router and Prefix Discovery\n");

static const char isatapd_dataname[] = N_("advertised prefixes");

typedef struct nd_router_solicit solicit_packet;

static ssize_t
buildsol (solicit_packet *rs, struct sockaddr_in6 *tgt,
	  const char *ifname)
{
	(void)tgt;
	(void)ifname;

	/* builds ICMPv6 Router Solicitation packet */
	rs->nd_rs_type = ND_ROUTER_SOLICIT;
	rs->nd_rs_code = 0;
	rs->nd_rs_cksum = 0; /* computed by the kernel */
	rs->nd_rs_reserved = 0;
	return sizeof (*rs);
}


static void
print32time (uint32_t v)
{
	v = ntohl (v);

	if (v == 0xffffffff)
		fputs (_("    infinite (0xffffffff)\n"), stdout);
	else
		printf (_("%12u (0x%08x) %s\n"),
		        v, v, ngettext ("second", "seconds", v));
}


static int
parseprefix (const struct nd_opt_prefix_info *pi, size_t optlen,
			 bool verbose)
{
	char str[INET6_ADDRSTRLEN];

	if (optlen < sizeof (*pi))
		return -1;

	/* displays prefix informations */
	if (inet_ntop (AF_INET6, &pi->nd_opt_pi_prefix, str,
	               sizeof (str)) == NULL)
		return -1;

	if (verbose)
	{
		fputs (_(" Prefix                   : "), stdout);
		printf ("%s/%u\n", str, pi->nd_opt_pi_prefix_len);
	}

	if (verbose)
	{
		fputs (_("  Valid time              : "), stdout);
		print32time (pi->nd_opt_pi_valid_time);
		fputs (_("  Pref. time              : "), stdout);
		print32time (pi->nd_opt_pi_preferred_time);
	}
	return 0;
}


static void
parsemtu (const struct nd_opt_mtu *m)
{
	unsigned mtu = ntohl (m->nd_opt_mtu_mtu);

	fputs (_(" MTU                      : "), stdout);
	printf ("       %5u %s (%s)\n", mtu,
	        ngettext ("byte", "bytes", mtu),
		gettext((mtu >= 1280) ? N_("valid") : N_("invalid")));
}


static const char *
pref_i2n (unsigned val)
{
	static const char *values[] =
		{ N_("medium"), N_("high"), N_("medium (invalid)"), N_("low") };
	return gettext (values[(val >> 3) & 3]);
}


static int
parseroute (const uint8_t *opt)
{
	uint8_t optlen = opt[1], plen = opt[2];
	if ((optlen > 3) || (plen > 128) || (optlen < ((plen + 127) >> 6)))
		return -1;

	char str[INET6_ADDRSTRLEN];
	struct in6_addr dst = in6addr_any;
	memcpy (dst.s6_addr, opt + 8, (optlen - 1) << 3);
	if (inet_ntop (AF_INET6, &dst, str, sizeof (str)) == NULL)
		return -1;

	printf (_(" Route                    : %s/%u\n"),
		str, (unsigned)plen);
	printf (_("  Route preference        :       %6s\n"),
		pref_i2n (opt[3]));
	fputs (_("  Route lifetime          : "), stdout);
	print32time (((const uint32_t *)opt)[1]);
	return 0;
}


static int
parserdnss (const uint8_t *opt)
{
	uint8_t optlen = opt[1];
	if (((optlen & 1) == 0) || (optlen < 3))
		return -1;

	optlen /= 2;
	for (unsigned i = 0; i < optlen; i++)
	{
		char str[INET6_ADDRSTRLEN];

		if (inet_ntop (AF_INET6, opt + (16 * i + 8), str,
		    sizeof (str)) == NULL)
			return -1;

		printf (_(" Recursive DNS server     : %s\n"), str);
	}

	fputs (ngettext ("  DNS server lifetime     : ",
	                 "  DNS servers lifetime    : ", optlen), stdout);
	print32time (((const uint32_t *)opt)[1]);
	return 0;
}


static int
parseadv (const uint8_t *buf, size_t len,
          const struct sockaddr_in6 *tgt,
          bool verbose, struct prl_element *curr_prl_el){

	const struct nd_router_advert *ra =
		(const struct nd_router_advert *)buf;
	const uint8_t *ptr;

	struct timespec	firein;

	(void)tgt;

	/* checks if the packet is a Router Advertisement */
	if ((len < sizeof (struct nd_router_advert)) ||
	    (ra->nd_ra_type != ND_ROUTER_ADVERT) ||
	    (ra->nd_ra_code != 0))
		return -1;

	if (verbose)
	{
		unsigned v;

		/* Hop limit */
		puts ("");
		fputs (_("Hop limit                 :    "), stdout);
		v = ra->nd_ra_curhoplimit;
		if (v != 0)
			printf (_("      %3u"), v);
		else
			fputs (_("undefined"), stdout);
		printf (_(" (      0x%02x)\n"), v);

		v = ra->nd_ra_flags_reserved;
		printf (_("Stateful address conf.    :          %3s\n"),
		        gettext((v & ND_RA_FLAG_MANAGED) ? N_ ("Yes") : N_("No")));
		printf (_("Stateful other conf.      :          %3s\n"),
		        gettext((v & ND_RA_FLAG_OTHER) ? N_ ("Yes") : N_("No")));
		printf (_("Router preference         :       %6s\n"),
				pref_i2n (v));

		/* Router lifetime */
		fputs (_("Router lifetime           : "), stdout);
		v = ntohs (ra->nd_ra_router_lifetime);
		printf (_("%12u (0x%08x) %s\n"), v, v,
		        ngettext ("second", "seconds", v));

		/* ND Reachable time */
		fputs (_("Reachable time            : "), stdout);
		v = ntohl (ra->nd_ra_reachable);
		if (v != 0)
			printf (_("%12u (0x%08x) %s\n"), v, v,
			        ngettext ("millisecond", "milliseconds", v));
		else
			fputs (_(" unspecified (0x00000000)\n"), stdout);

		/* ND Retransmit time */
		fputs (_("Retransmit time           : "), stdout);
		v = ntohl (ra->nd_ra_retransmit);
		if (v != 0)
			printf (_("%12u (0x%08x) %s\n"), v, v,
			        ngettext ("millisecond", "milliseconds", v));
		else
			fputs (_(" unspecified (0x00000000)\n"), stdout);
	}

	/* RFC 5214 8.3.4, extract the router lifetime from RA and
	 * set timer for the next RS
	 */

	/**TODO:Include Prefix/Route Information Option lifetimes **/
	double router_lifetime; /* in secs */
	unsigned v;
	v = ntohs (ra->nd_ra_router_lifetime);
	if (v != 0)
	{
		router_lifetime = (double)v * 0.8; /* 80% of lifetime */
		/* set router_lifetime to a max of 10min (600s + [0,1))*/
		if (router_lifetime > 600.0)
			router_lifetime = 600.0 +
					  ((double)rand() / RAND_MAX);

		if ((isflags & IS_VERBOSE) > IS_VERBOSE1)
		{
			printf("[DEBUG parseadv %i], ",getpid());
			printf("reset router lifetime by %.2f\n",
				router_lifetime);
		}
	}
	else
	{
		/* if router_life time is not specified,
		 * use the DEFAULT_MinRouterSolicitInterval
		 */
		router_lifetime =
			(double) DEFAULT_MinRouterSolicitInterval;

		if ((isflags & IS_VERBOSE) > IS_VERBOSE1)
		{
			printf("[DEBUG parseadv %i], router lifetime ",
				getpid());
			printf("unspecified or 0, use default %.2f\n",
				router_lifetime);
		}
	}

	len -= sizeof (struct nd_router_advert);

	/* parses options */
	ptr = buf + sizeof (struct nd_router_advert);

	while (len >= 8)
	{
		uint16_t optlen;

		optlen = ((uint16_t)(ptr[1])) << 3;
		if ((optlen == 0) || /* invalid length */
		    (len < optlen) /* length > remaining bytes */)
			break;

		len -= optlen;

		/* only prefix are shown if not verbose */
		switch (ptr[0] * (verbose ? 1:
			(ptr[0] == ND_OPT_PREFIX_INFORMATION)))
		{
			case ND_OPT_SOURCE_LINKADDR:
				fputs (_(" Source link-layer address: "),
					stdout);
				printmacaddress (ptr + 2, optlen - 2);
				break;

			case ND_OPT_TARGET_LINKADDR:
				break; /* ignore */

			case ND_OPT_PREFIX_INFORMATION:
				if (parseprefix ((const struct nd_opt_prefix_info *)ptr,
				                 optlen, verbose))
					return -1;

			case ND_OPT_REDIRECTED_HEADER:
				break; /* ignore */

			case ND_OPT_MTU:
				parsemtu ((const struct nd_opt_mtu *)ptr);
				break;

			case 24: /* RFC4191 */
				parseroute (ptr);
				break;

			case 25: /* RFC Ed queued draft-jeong-dnsop-ipv6-dns-discovery-12 */
				parserdnss (ptr);
				break;
		}
		/* skips unrecognized option */

		ptr += optlen;
	}



	/* resend RS when you're 80% of router_lifetime but < 10min*/
	firein.tv_sec = (long) router_lifetime;
	firein.tv_nsec = (long) ((router_lifetime - firein.tv_sec) *
                         1000000000);
	if (insert_prl(firein, curr_prl_el) == -1)
	{
		printf("[ERROR parseadv] Error inserting PRL");
		return -1;
	}
	else
	{
		if ((isflags & IS_VERBOSE) > IS_VERBOSE1)
		{
			printf("[DEBUG parseadv pid] ");
			printf(" Inserted into PRL fire at %ld secs %ld nsecs\n",
			curr_prl_el->alarm.tv_sec,
			curr_prl_el->alarm.tv_nsec);
		}
	}
	if (set_timer(timer_id) == -1)
	{
		printf("[ERROR parseadv] Error setting timer");
		return -1;
	}

	return 0;
}



static ssize_t
recvfromLL (int fd, void *buf, size_t len, int flags,
            struct sockaddr_in6 *addr)
{
	char cbuf[CMSG_SPACE (sizeof (int))];
	struct iovec iov =
	{
		.iov_base = buf,
		.iov_len = len
	};
	struct msghdr hdr =
	{
		.msg_name = addr,
		.msg_namelen = sizeof (*addr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof (cbuf)
	};

        ssize_t val = recvmsg (fd, &hdr, flags);
        if (val == -1)
		return val;


	/* ensures the hop limit is 255 */
	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR (&hdr);
	     cmsg != NULL;
	     cmsg = CMSG_NXTHDR (&hdr, cmsg))
	{
		if ((cmsg->cmsg_level == IPPROTO_IPV6)
		 && (cmsg->cmsg_type == IPV6_HOPLIMIT))
		{
			if (255 != *(int *)CMSG_DATA (cmsg))
			{
				/* pretend to be a spurious wake-up */
				errno = EAGAIN;
				return -1;
			}
		}
	}

	return val;
}

/*
 * This routine is only called when a router advertisement is received
 * After receiving the RA find the router in the PRL that sent this RA
 *      Extract this element from the PRL
 *      Extract the router_lifetime from the RA
 *      Reset alarm for this PRL element to + 80% of the router_lifetime
 *      Insert into the PRL in ascending order of firing
 *      Set the timer to fire for the first element in the PRL
 *      NB: the last 4 steps are performed in parseadv()
 */

static ssize_t
recvadv(int fd)
{
        struct prl_element *next_prl_el = NULL;
        struct prl_element *prev_prl_el = NULL;
        struct prl_element *curr_prl_el = NULL;
	ssize_t val = 0;

	/* receives an ICMPv6 packet */
	/**TODO: use interface MTU as buffer size **/

	uint8_t buf[1460];
	struct sockaddr_in6 addr;

        val = recvfromLL (fd, buf, sizeof (buf),
                                MSG_WAITALL, &addr);
	if (val == -1)
	{
                if (errno == EINTR)
                {
                    if ((isflags & IS_VERBOSE) > IS_VERBOSE2)
                        perror(_("Receive interrupted by signal"));
                }
                else if (errno != EAGAIN)
			perror (_("Receiving ICMPv6 packet"));
		return val;
	}

        sigset_t        mask;

        /* Block timer signal temporarily while using PRL and setting timer */
        sigemptyset(&mask);
        sigaddset(&mask, SIG_TIMER);
        if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1)
        {
                printf("[ERROR recvadv] sigprocmask\n");
                return -1;
        }

	/* When the  process receives a RA it scans the PRL*/
	/* to find the correct router by comparing the senders*/
	/* address with the target address from each element of the PRL*/
	curr_prl_el = prl_head;
	while ((curr_prl_el->next != NULL) &&
	       bcmp(&addr.sin6_addr.s6_addr,
	            &curr_prl_el->tgt.sin6_addr.s6_addr, 16)!= 0)
	{
                prev_prl_el = curr_prl_el;
		curr_prl_el = curr_prl_el -> next;
	}
	if (bcmp(&addr.sin6_addr.s6_addr,
	    &curr_prl_el->tgt.sin6_addr.s6_addr, 16)== 0)
	{
	        /* found the prl element with the same address*/
		if ((isflags & IS_VERBOSE) > IS_VERBOSE1)
                {
                        char str1[INET6_ADDRSTRLEN];
                        char str2[INET6_ADDRSTRLEN];
                        printf("[DEBUG recvadv]");
                        if (inet_ntop (AF_INET6, &addr.sin6_addr,
                            str1, sizeof (str1)) != NULL)
                                printf ("RA rec from addr %s ", str1);
                        if (inet_ntop (AF_INET6, &curr_prl_el->tgt.sin6_addr,
                            str2, sizeof (str2)) != NULL)
                                printf ("current prl el tgt addrs %s\n", str2);
                }

                /* ensures the response came through the right interface */
                if (addr.sin6_scope_id
                   && (addr.sin6_scope_id != curr_prl_el->tgt.sin6_scope_id))
                {
			if ((isflags & IS_VERBOSE) > IS_VERBOSE1)
                        {
                           printf("[ERROR recvadv] RA did not come through "
                                  "on the right interface\n");
                        }
                        val = -1;
                }
                else
                {
                        /* extract the prl element from the PRL*/
                        if (curr_prl_el == prl_head)
                        {
                                prl_head = curr_prl_el->next;
                        }
                        else
                        {
                                if (curr_prl_el->next != NULL)
                                {
                                prev_prl_el->next = curr_prl_el->next;
                                next_prl_el = curr_prl_el->next;
                                next_prl_el->prev = prev_prl_el;
                        }
                      	else
                                prev_prl_el->next = NULL;
                        }
                        curr_prl_el -> prev = NULL;
                        curr_prl_el -> next = NULL;
                        curr_prl_el -> retry = 0;
                        curr_prl_el -> timer_set = 0;

                        /* parse the RA which also insert curr_prl_el
                         * back into the PRL and set time*/
                        if (parseadv(buf, val, &(curr_prl_el->tgt),
                            (isflags & IS_VERBOSE) != 0, curr_prl_el) == 0)
                        {
				if ((isflags & IS_VERBOSE) > IS_VERBOSE1)
                                {
                                        char str[INET6_ADDRSTRLEN];
                                        if (inet_ntop (AF_INET6, &addr.sin6_addr,
					       str, sizeof (str)) != NULL)
                                                printf (_("Success return from "
                                                    "parseadv, RA from %s\n"), str);
                                }

                        }
                        else
                        {
                                if ((isflags & IS_VERBOSE) > IS_VERBOSE1)
                                {
                                        printf("[ERROR recvadv] parseadv "
                                            "returned error");
                                }
                                val = -1;
                        }
                }
	}
	else
	{
                /* cannot find the router in our PRL*/
		if ((isflags & IS_VERBOSE) > IS_VERBOSE1)
                {
                        printf ("[DEBUG recvadv] receive unsolicited RA\n");
                }
                val = -1;
	}

        /* Unlock the timer signal, so that timer notification can be sent */
        if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1)
        {
                printf("[ERROR recvadv] sigprocmask\n");
                val = -1;
        }
        return val;

}


static int fd;

/* This function will be executed when the timer goes off.
 * This will correspond to the first element(router) in the prl
 * When the timer goes off
 *      extract the first element from the PRL
 *      reset the timer to fire based on the new head element in PRL
 *      if so send RS,
 *      If this was the 1st or 2nd router solicitation (RS)
 *              reset alarm for this PRL element to +RTR_SOLICITATION_INTERVAL(4s)
 *              insert into the PRL in ascending order of firing
 *              set the timer to fire for the first element in the PRL
 *      If this was the 3rd RS
 *              reset alarm timer to +DEFAULT_MinRouterSolicitInterval(120s)
 *              insert into the PRL in ascending order of firing
 *              set the timer to fire for the first element in the PRL
 *
 */
static void
timer_handler(int signum, siginfo_t *info, void *context)
{
	sigset_t mask;
	struct timespec firein;
        int retry = MAX_RTR_SOLICITATIONS;
        int pid = getpid();
        char addr[INET6_ADDRSTRLEN];
        solicit_packet packet;
        struct sockaddr_in6 dst;
        ssize_t plen;
        struct prl_element *first_prl_el;


        sigemptyset(&mask);
        sigaddset(&mask, signum);

        /* Block timer signal temporarily while setting timer for the new prl head */
        if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1)
        {
                printf("[ERROR timer_handler] sigprocmask\n");
                raise(SIGKILL);
        }

	/* extract the first element from prl */
	first_prl_el = prl_head;
        first_prl_el->timer_set = 0;

        inet_ntop(AF_INET6, &(first_prl_el->tgt).sin6_addr, addr, sizeof (addr));
        if ((isflags & IS_VERBOSE) > IS_VERBOSE1)
        {
                printf("[DEBUG timer_handler %i] called for %s",
                        pid, addr);
                printf(" Caught signal %d\n", signum);
        }

	if (first_prl_el->next == NULL)
	{
		/* no elements left in the prl*/
		prl_head = NULL;
	}
	else
	{
		/* point to new element in head of prl*/
		prl_head = first_prl_el->next;
		prl_head->prev = NULL;

	        if (set_timer(timer_id) == -1)
	        {
	                printf("[ERROR timer_handler] Unable to set timer\n");
	        }
	}
	first_prl_el->prev = NULL;
        first_prl_el->next = NULL;

        /* Unlock the timer signal, so that timer notification can be sent */
        if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1)
        {
                printf("[ERROR timer_handler] sigprocmask\n");
                raise(SIGKILL);
        }


	memcpy (&dst, &(first_prl_el->tgt), sizeof (dst));
	plen = buildsol (&packet, &dst, first_prl_el->ifname);
	if (plen == -1)
		goto error;

	/* sends a Solitication */
	if (sendto (fd, &packet, plen, 0,
		    (const struct sockaddr *)&dst,
		    sizeof (dst)) != plen)
	{
		perror (_("Sending ICMPv6 packet"));
		goto error;
	}

        first_prl_el->retry++;
	if ((isflags & IS_VERBOSE) > IS_VERBOSE1)
	{
		printf("[DEBUG timer_handler pid %i] ",	pid);
		printf("sent RS %i to %s\n", first_prl_el->retry, addr);
	}

	if (first_prl_el->retry < MAX_RTR_SOLICITATIONS)
	{
                 /* re send RS in 4 sec */
                firein.tv_sec = (long) RTR_SOLICITATION_INTERVAL;
                firein.tv_nsec = (long) ((RTR_SOLICITATION_INTERVAL -
                                          firein.tv_sec) * 1000000000);
	}
	else if ((first_prl_el->retry) == MAX_RTR_SOLICITATIONS)
	{
                first_prl_el->retry = 0;

                /* retry in 2 min */
               firein.tv_sec = (long) DEFAULT_MinRouterSolicitInterval;
               firein.tv_nsec = (long) ((DEFAULT_MinRouterSolicitInterval -
                                         firein.tv_sec) * 1000000000);
	}

        /* Block timer signal temporarily while inserting into PRL & set timer */
        if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1)
        {
                printf("[ERROR timer_handler] sigprocmask\n");
                raise(SIGKILL);
        }
        if (insert_prl(firein, first_prl_el) == -1)
        {
                printf("[ERROR timer_handler] Error inserting into PRL\n");
                raise(SIGKILL);
        }
        else
        {
                if ((isflags & IS_VERBOSE) > IS_VERBOSE1)
                {
                        printf("[DEBUG timer_handler pid %i] ", pid);
                        printf(" Inserted into PRL fire at %ld secs %ld nsecs\n",
                                first_prl_el->alarm.tv_sec,
                                first_prl_el->alarm.tv_nsec);
                }
        }
        if (set_timer(timer_id) == -1)
        {
                printf("[ERROR timer_handler] Unable to set timer");
        }
        /* Unlock the timer signal, so that timer notification can be sent */
        if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1)
        {
                printf("[ERROR timer_handler] sigprocmask\n");
                raise(SIGKILL);
        }
	return;

error:
	if ((isflags & IS_VERBOSE) > IS_VERBOSE1)
	{
		printf("[ERROR timer_handler pid %i] problem ",pid);
		printf("with creating or sending RS\n");
	}
	raise(SIGKILL);

}
/* end of timer_handler*/


static int
isatapd (char *ipv4[], char *ifname, unsigned retry, unsigned wait_ms)
{
	double rand_ini_delay;
	struct sockaddr_in6 tgt;
	struct prl_element *scan_prl;
	struct prl_element *new_prl_el;
	int dup;
	sigset_t mask;
	struct timespec     firein;
	int pid;
	int status;
        struct sigevent signal_event;
        char addr[INET6_ADDRSTRLEN];

        fd = socket (PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        /* Drops root privileges (if setuid not run by root).
         * Also make sure the socket is not STDIN/STDOUT/STDERR.
         */
        if (setuid (getuid ()) || ((fd >= 0) && (fd <= 2)))
                return -1;

	if ((isflags & IS_VERBOSE) > IS_VERBOSE2)
	{
		printf("[DEBUG isatapd] called with ifname %s ipv4 ",
			ifname);
		int i;
		for (i=0; ipv4[i] != NULL; i++)
			printf(" %s ", ipv4[i]);
		printf("\n");
	}

	if (fd == -1)
	{
		perror (_("Raw IPv6 socket"));
		return -1;
	}

	fcntl (fd, F_SETFD, FD_CLOEXEC);

	/* set ICMPv6 filter */
	{
		struct icmp6_filter f;

		ICMP6_FILTER_SETBLOCKALL (&f);
		ICMP6_FILTER_SETPASS (nd_type_advert, &f);
		setsockopt (fd, IPPROTO_ICMPV6, ICMP6_FILTER,
			    &f, sizeof (f));
	}

	setsockopt (fd, SOL_SOCKET, SO_DONTROUTE,
		    &(int){ 1 }, sizeof (int));

	/* sets multicast Hop-by-hop limit to 255 */
	setmcasthoplimit (fd, 255);

	/* set unicast Hop limit to 255 */
	setucasthoplimit (fd, 255);

	setsockopt (fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
	            &(int){ 1 }, sizeof (int));



	pid = fork();
        if (pid > 0)
        {
		/* continue with parent process */
                if ((isflags & IS_VERBOSE) > IS_VERBOSE2)
                {
                        printf("[DEBUG isatapd pid %i] ", pid);
                        printf("continue with parent proc\n");
                }

                /* wait for child process */
		printf ("pid %i ", wait(&status));
		if (WIFEXITED(status))
			printf("exited, status=%d\n", WEXITSTATUS(status));
		else if (WIFSIGNALED(status))
			printf("killed by signal %d\n", WTERMSIG(status));
		else if (WIFSTOPPED(status))
                       printf("stopped by signal %d\n", WSTOPSIG(status));
		else if (WIFCONTINUED(status))
                       printf("continued\n");
		printf ("parent process %i ending \n",getpid());
         }
        else if (pid == 0)
	{
                int childpid = getpid();
                /* child process to handle solicited RS and RA*/
		if ((isflags & IS_VERBOSE) > IS_VERBOSE1)
		{
			printf("[DEBUG isatapd %i] ",
					childpid);
			printf(" for each prl send RS\n");
		}

		/**TODO: PRL re-initialisation.
		 *	 RFC5214 8.3.2 2nd paragraph
		 **/

		/* set up sigaction for timer handler*/
		signal_action.sa_flags = SA_SIGINFO;
		signal_action.sa_sigaction = timer_handler;
		sigemptyset(&signal_action.sa_mask);
		if (sigaction(SIG_TIMER, &signal_action, NULL) == -1)
		{
                        printf("[ERROR isatapd] sigaction");
                        return -1;
		}

		/* initialize mask with SIG TIMER*/
		sigemptyset(&mask);
		sigaddset(&mask, SIG_TIMER);
		if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1)
		{
		        printf("[ERROR isatapd] sigprocmask");
		        return -1;;
		}

		/* create timer*/
		signal_event.sigev_notify = SIGEV_SIGNAL;
		signal_event.sigev_signo = SIG_TIMER;
		signal_event.sigev_value.sival_ptr = &timer_id;
		if (timer_create(CLOCK_REALTIME, &signal_event, &timer_id) < 0)
		{
		        /* ERROR SETTING UP TIMER*/
		        printf("[ERROR isatapd] timer_create");
		        return -1;
		}

		/* for each ip address, create an element in the prl */
		for (int i = 0; ipv4[i] != NULL; i++)
		{
			/* resolves target's IPv6 address */
			if (getipv6byname(ipv4[i], ifname,
					  (isflags & IS_NUMERIC) ? 1 : 0,
					  &tgt))
			{
				if ((isflags & IS_VERBOSE) > IS_VERBOSE1)
				{
					printf("[DEBUG isatapd %i] Error ret ",
						   childpid);
					printf("from getipv6byname(), ipv4 %s\n",
						   ipv4[i]);
				}
				close (fd);
			}
			else
			{
				/* see if we already have this one in the list*/
				dup = 0;
				for (scan_prl=prl_head; scan_prl;
				     scan_prl=scan_prl->next)
				{
					if (!(bcmp (&scan_prl->tgt.sin6_addr.s6_addr,
						    &tgt.sin6_addr.s6_addr, 16)))
					{
						dup++;
						break;
					}
				}

				if (dup)
				{
					if (isflags & IS_VERBOSE)
					{
						printf (_("%s is a duplicate...\n"),
							ipv4[i]);
					}
					continue;
				}

				/* Create and store the prl element */
				char s[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, &tgt.sin6_addr,
					  s, sizeof (s));
				if ((isflags & IS_VERBOSE) == IS_VERBOSE3)
				{
					printf("[DEBUG isatapd %i] ",
						childpid);
					printf("Converted to ipv6 %s ",
						s);
					printf("from ipv4 %s\n", ipv4[i]);
				}

				if (isflags & IS_VERBOSE)
				{
					printf (_("Soliciting %s (%s) on %s...\n"),
						ipv4[i], s, ifname);
				}

				char *copy_ifname;
				copy_ifname = (char *)
						malloc(100 * sizeof(char));
				strcpy(copy_ifname,ifname);

				new_prl_el =(struct prl_element *)
					     malloc(sizeof(struct prl_element));
				new_prl_el->wait_ms = wait_ms;
				new_prl_el->ifname = copy_ifname;
				new_prl_el->tgt = tgt;
				new_prl_el->next = NULL;
				new_prl_el->prev = NULL;
				new_prl_el->timer_set = 0;
                                new_prl_el->retry = 0;

				/*prl_el = new_prl_el;*/

				/* RFC 4861 sect 6.3.7, Before
				 * sending initial RS, delay by
				 * [0..MAX_RTR_SOLICITATION_DELAY]
				 */
				/**TODO: use system clock as the seed to
				 *	 the random number generator
				 **/
				rand_ini_delay = (double)rand() *
						 (double)MAX_RTR_SOLICITATION_DELAY /
						 (double)RAND_MAX;

				/* Block timer signal temporarily while setting timer */
				if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1)
				{
					printf("[ERROR isatapd] sigprocmask\n");
					return -1;
				}

				firein.tv_sec = (long) rand_ini_delay;
				firein.tv_nsec = (long) ((rand_ini_delay -
                                                 firein.tv_sec) * 1000000000);
				if (insert_prl(firein, new_prl_el) == -1)
                                {
                                        printf("[ERROR isatapd] Error inserting into PRL");
                                        return -1;
                                }
		                else
		                {
		                        if ((isflags & IS_VERBOSE) > IS_VERBOSE1)
		                        {
		                                printf("[DEBUG isatapd pid %i] ", childpid);
		                                printf(" Inserted into PRL fire at %ld secs %ld nsecs\n",
		                                     new_prl_el->alarm.tv_sec,
		                                     new_prl_el->alarm.tv_nsec);
		                        }
		                }
				if (set_timer(timer_id) == -1)
				{
	        			printf("[ERROR isatapd] Unable to set timer");
	        			return -1;
				}

				/* Unlock the timer signal, so that timer notification */
				/* can be sent */
				if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1)
				{
					printf("[ERROR isatapd] sigprocmask\n");
					return -1;
				}
			}
		}


		if (prl_head == NULL)
		{
			if ((isflags & IS_VERBOSE) > IS_VERBOSE1)
			{
				printf("[DEBUG isatapd %i] no PRL created\n", childpid);
				return -1;
			}
		}
		else
		{
			if ((isflags & IS_VERBOSE) > IS_VERBOSE1)
			{
				struct timespec c_time;
				struct itimerspec itime;
				clock_gettime(CLOCK_REALTIME, &c_time);
				timer_gettime(timer_id,&itime);

				printf("[DEBUG isatapd %i] PRL created\n",
				        childpid);
                		printf("[DEBUG isatapd] current time %ld secs %ld nsecs\n",
					c_time.tv_sec, c_time.tv_nsec);
				printf("[DEBUG isatapd] timer to fire in %ld secs %ld nsecs\n",
					prl_head->alarm.tv_sec,
					prl_head->alarm.tv_nsec);
				printf("[DEBUG isatapd] time left %ld secs %ld nsecs\n",
					itime.it_value.tv_sec,
					itime.it_value.tv_nsec);
			}

			for (;;)
			{
		                /* receives an Advertisement, and reset the timer
		                 * in parseAdv */
		                ssize_t val = recvadv (fd);

		                if (val > 0)
		                {
		                        if ((isflags & IS_VERBOSE) > IS_VERBOSE1)
		                        {
		                                printf("[DEBUG isatapd %i] ",
		                                        childpid);
		                                printf(" RA packet size = %i\n",val);
		                        }
		                }
			}
		}
	}
	else if (pid < 0)
	{
		/* Error occured while trying to create
		   child process to handle RS and RA
		 */
		printf("[ERROR isatapd] failed to create ");
		printf("process to handle Router ");
		printf("Solicitations and Advertisments\n");
		return -1;
	}


return 0;
}

static int
quick_usage (const char *path)
{
	fprintf (stderr, _("Try \"%s -h\" for more information.\n"),
		 path);
	return 2;
}


static int
usage (const char *path)
{
	printf (gettext (isatapd_usage), path);

	printf (_("\n"
"[options]\n"
"  -h, --help     display this help and exit\n"
"  -d, --dev      device name (default: 'is0')\n"
"  -p, --prl      Potential Router List (PRL) name\n"
"  -q, --quiet    only print the %s (mainly for scripts)\n"
"  -r, --retry    maximum number of attempts (default: 3)\n"
"  -V, --version  display program version and exit\n"
"  -v, --verbose  print debug messages on screen\n"
"  -w, --wait     how long to wait for a response [ms] (default: 1000)\n"
" example:\n"
"	./isatapd -d is1 -p isatap.example.com\n"
"	./isatapd -v -p isatap.example.com\n"
"	./isatapd -r 5 -p isatap.example.com\n"
"	./isatapd -d is1 192.168.1.1 192.168.1.2 192.168.1.3"
"\n"), gettext (isatapd_dataname));
	return 0;
}

static int
version (void)
{
	printf (_(
"isatapd: ISATAP Router and Prefix Discovery userland tool %s (%s)\n"), VERSION, "$Rev: 483 $");
	printf (_(" built %s on %s\n"), __DATE__, PACKAGE_BUILD_HOSTNAME);

	printf (_("Configured with: %s\n"), PACKAGE_CONFIGURE_INVOCATION);
	puts (_("Written by Remi Denis-Courmont\n"));
	puts (_("Adapted for ISATAP by Kwong-Sang Yin and Fred Templin\n"));

	printf (_("Copyright (C) %u-%u Remi Denis-Courmont\n"
"Copyright (C) %u-%u The Boeing Company\n"
"This is free software; see the source for copying conditions.\n"
"There is NO warranty; not even for MERCHANTABILITY or\n"
"FITNESS FOR A PARTICULAR PURPOSE.\n"), 2004, 2006, 2008, 2009);
	return 0;
}

static const struct option opts[] =
{
	{ "help",	no_argument,		NULL, 'h' },
	{ "dev",	required_argument,	NULL, 'd' },
	{ "prl",	required_argument,	NULL, 'p' },
	{ "quiet",	no_argument,		NULL, 'q' },
	{ "retry",	required_argument,	NULL, 'r' },
	{ "version",	no_argument,		NULL, 'V' },
	{ "verbose",	no_argument,		NULL, 'v' },
	{ "wait",	required_argument,	NULL, 'w' },
	{ NULL,		0,			NULL, 0   }
};


int
main (int argc, char *argv[])
{
	/*fd = socket (PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);*/
	int errval = errno;

	/*** added signal var*/
	sigset_t oset, nset;

	/* Drops root privileges (if setuid not run by root).
	 * Also make sure the socket is not STDIN/STDOUT/STDERR.
	 */
	/*if (setuid (getuid ()) || ((fd >= 0) && (fd <= 2)))
		return 1;*/

	setlocale (LC_ALL, "");
	bindtextdomain (PACKAGE, LOCALEDIR);
	textdomain (PACKAGE);

	int val, i = 0;
	unsigned retry = 3, wait_ms = nd_delay_ms;
	char *v4addr[51], *ifname = "is0", *prlname = NULL;

	/* extract optional arguments*/
	while ((val = getopt_long (argc, argv, "hd:p:qr:Vvw:", opts, NULL)) != EOF)
	{
		switch (val)
		{
			case 'h':
				return usage (argv[0]);

			case 'd':
			{
				ifname = optarg;
				break;
			}
			case 'p':
			{
				prlname = optarg;
				break;
			}
			case 'q':
				isflags &= ~IS_VERBOSE;
				break;

			case 'r':
			{
				unsigned long l;
				char *end;

				l = strtoul (optarg, &end, 0);
				if (*end || l > UINT_MAX)
					return quick_usage (argv[0]);
				retry = l;
				break;
			}

			case 'V':
				return version ();

			case 'v':
				/* NOTE: assume IS_VERBOSE occupies low-order bits */
				if ((isflags & IS_VERBOSE) < IS_VERBOSE)
					isflags++;
				break;

			case 'w':
			{
				unsigned long l;
				char *end;

				l = strtoul (optarg, &end, 0);
				if (*end || l > UINT_MAX)
					return quick_usage (argv[0]);
				wait_ms = l;
				break;
			}

			case '?':
			default:
				return quick_usage (argv[0]);
		}
	}

	/* get PRL by name */
	if (prlname)
	{
		struct hostent *hentptr;
		hentptr = gethostbyname(prlname);
		if ((hentptr == NULL) || ((int)hentptr == -1))
		{
			if (isflags & IS_VERBOSE)
			{
				printf("[ERROR main pid %i] ", getpid());
				printf("PRL name \"%s\": unknown\n", prlname);
			}
			return quick_usage (argv[0]);
		}
		else if (hentptr->h_addr_list == NULL)
		{
			if (isflags & IS_VERBOSE)
			{
				printf("[ERROR main pid %i] ", getpid());
				printf("PRL name \"%s\": empty\n", prlname);
			}
			return quick_usage (argv[0]);
		}
		else
		{
			/* extract all ipv4 addresses received from DNS */
			struct in_addr **pptr;
			pptr = (struct in_addr **)hentptr->h_addr_list;
			for (; ((*pptr != NULL) && (i < 50)); pptr++, i++)
			{
				v4addr[i] = malloc(16*sizeof(char));
				strcpy(v4addr[i],inet_ntoa(**pptr));
			}
		}
	}

	/* add any IPv4 addresses*/
	for (; ((optind < argc) && (i < 50)); optind++, i++) {
		v4addr[i] = argv[optind];
		if (inet_addr(v4addr[i]) == -1 )
		{
			/* also catches 255.255.255.255 (i.e. an invalid PRL) */
			if (isflags & IS_VERBOSE)
			{
				printf("[ERROR main pid %i] ", getpid());
				printf("%s not a valid PRL address\n", v4addr[i]);
			}
			return quick_usage (argv[0]);
		}
	}

	if (i == 0)
	{
		if (isflags & IS_VERBOSE)
		{
			printf("[ERROR main], no hostname or ipv4 ");
			printf("addresses in command \n ");
		}
		return quick_usage (argv[0]);
	}

	v4addr[i] = NULL;

	/* if the user included a valid interface (dev option) use it
	 * otherwise default to is0
	 */
	if (if_nametoindex (ifname) == 0)
	{
		if (isflags & IS_VERBOSE) {
			printf("[ERROR main]: %s: no such interface\n", ifname);
		}

		return quick_usage (argv[0]);
	}

	int ret_val1 = isatapd (v4addr, ifname, retry, wait_ms);
	return -ret_val1;
}

