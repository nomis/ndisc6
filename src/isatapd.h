/* from ndisc.c in 'ndisc6-0.9.8' distribution */
enum isatap_flags
{
	IS_VERBOSE1=0x1,
	IS_VERBOSE2=0x2,
	IS_VERBOSE3=0x3,
	IS_VERBOSE =0x3,
	IS_NUMERIC =0x4,
	IS_SINGLE  =0x8,
};

/*
 * ISATAP Router Discovery [RFC5214]
 * (c)2008-2009 the Boeing Company.
 *
 * Kwong-Sang Yin <kwong-sang.yin@boeing.com>
 * Fred Templin <fred.l.templin@boeing.com>
 *
 * isatapd.h - v0.1 (5/29/09)
 * /

/* Host Constants from rfc4861*/
#define         MAX_RTR_SOLICITATION_DELAY       1 /*secs*/
#define         RTR_SOLICITATION_INTERVAL        4 /*secs*/
#define         MAX_RTR_SOLICITATIONS            3 /*transmissions*/

/* Node Constants from rfc4861*/
#define         MAX_MULTICAST_SOLICIT            3 /*transmissions*/
#define         MAX_UNICAST_SOLICIT              3 /*transmissions*/
#define         MAX_ANYCAST_DELAY_TIME           1 /*secs*/
#define         MAX_NEIGHBOR_ADVERTISEMENT       3 /*transmissions*/
#define         REACHABLE_TIME                   30000 /*msecs*/
#define         RETRANS_TIMER                    1000 /*msecs*/
#define         DELAY_FIRST_PROBE_TIME           5 /*secs*/
#define         MIN_RANDOM_FACTOR                .5
#define         MAX_RANDOM_FACTOR                1.5

/* Default Host Variable from rfc5214*/
#define         DEFAULT_PrlRefreshInterval       3600 /*secs*/
#define         DEFAULT_MinRouterSolicitInterval 120 /*secs*/

/*timer signal*/
#define         SIG_TIMER                        SIGRTMIN

/*
 * Potential Router List(prl) element is made up of a
 * - Timer indicating when a router solicitation should be sent
 * - IPv4 Address of the router's advertising ISATAP interface
 * - next alarm indicates when to send a RS to the IPv4 Addr
 * - timer_set indicates if the timer is set for this router
*/
struct prl_element
{
	struct timespec		alarm;
	char			*ifname;
	unsigned		wait_ms;
	struct sockaddr_in6	tgt;
	struct prl_element	*next;
	struct prl_element	*prev;
	int			timer_set;
	int			retry;
};

extern unsigned isflags;
