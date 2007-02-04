#ifndef EZIRAD_EZIRAD_H
# define EZIRAD_EZIRAD_H 1

typedef struct ez_addr
{
	struct sockaddr_in6 addr;
	unsigned            prefix_length;
} ez_addr_t;


int ezsys_init (void);
void ezsys_deinit (void);
void ezsys_process (void);

unsigned ezsys_nifaces (void);
unsigned ezsys_getifaces (unsigned *restrict ifaces, unsigned size);
unsigned ezsys_naddrs (void);
unsigned ezsys_getaddresses (ez_addr_t *restrict ifaces, unsigned size);

uint32_t ezsys_get_mtu (int ifindex);
size_t ezsys_get_hwaddr (int ifindex, uint8_t *restrict buf, size_t buflen);

#endif
