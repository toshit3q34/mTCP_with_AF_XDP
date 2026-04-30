#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/ip.h>

#include "ip_in.h"
#include "tcp_in.h"
#include "mtcp_api.h"
#include "ps.h"
#include "debug.h"
#include "icmp.h"

#define ETH_P_IP_FRAG   0xF800
#define ETH_P_IPV6_FRAG 0xF6DD

/*----------------------------------------------------------------------------*/
inline int 
ProcessIPv4Packet(mtcp_manager_t mtcp, uint32_t cur_ts, 
				  const int ifidx, unsigned char* pkt_data, int len)
{
	/* check and process IPv4 packets */
	struct iphdr* iph = (struct iphdr *)(pkt_data + sizeof(struct ethhdr));
	int ip_len = ntohs(iph->tot_len);
	int rc = -1;

	/* drop the packet shorter than ip header */
	if (ip_len < sizeof(struct iphdr))
		return ERROR;

#ifndef DISABLE_HWCSUM
	if (mtcp->iom->dev_ioctl != NULL)
		rc = mtcp->iom->dev_ioctl(mtcp->ctx, ifidx, PKT_RX_IP_CSUM, iph);
	if (rc == -1 && ip_fast_csum(iph, iph->ihl))
		return ERROR;
#else
	UNUSED(rc);
	if (ip_fast_csum(iph, iph->ihl))
		return ERROR;
#endif

#if !PROMISCUOUS_MODE
	/* if not promiscuous mode, drop if the destination is not myself */
	if (iph->daddr != CONFIG.eths[ifidx].ip_addr) {
		/* Diagnostic for the silent drop case — most common reason
		 * packets surface in recv_pkts but never reach the TCP stack.
		 * Rate-limited to first 16 drops. */
		static __thread uint64_t dropped = 0;
		if (dropped < 16) {
			dropped++;
			uint8_t *d = (uint8_t *)&iph->daddr;
			uint8_t *m = (uint8_t *)&CONFIG.eths[ifidx].ip_addr;
			fprintf(stderr,
				"ip_in: DROP ifidx=%d daddr=%u.%u.%u.%u != my_ip=%u.%u.%u.%u proto=%u\n",
				ifidx, d[0], d[1], d[2], d[3], m[0], m[1], m[2], m[3],
				iph->protocol);
		}
		//DumpIPPacketToFile(stderr, iph, ip_len);
		return TRUE;
	}
#endif

	// see if the version is correct
	if (iph->version != 0x4 ) {
		mtcp->iom->release_pkt(mtcp->ctx, ifidx, pkt_data, len);
		return FALSE;
	}
	
	switch (iph->protocol) {
		case IPPROTO_TCP:
			return ProcessTCPPacket(mtcp, cur_ts, ifidx, iph, ip_len);
		case IPPROTO_ICMP:
			return ProcessICMPPacket(mtcp, iph, ip_len);
		default:
			/* currently drop other protocols */
			return FALSE;
	}
	return FALSE;
}
/*----------------------------------------------------------------------------*/
