/*-
 * Copyright (c) <2010-2017>, Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* Created 2010 by Keith Wiles @ intel.com */

#include <cli_scrn.h>
#include "pktgen-arp.h"

#include "pktgen.h"
#include "pktgen-cmds.h"
#include "pktgen-log.h"

/* #define DEBUG */


/**************************************************************************//**
 *
 * pktgen_dump_arp - DUMP an ARP packet.
 *
 * DESCRIPTION
 * Dump an ARP packet in fptr.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
pktgen_dump_arp(FILE *fptr, arpPkt_t *arp, struct ether_hdr *eth)
{
	 char ip_addr[2][INET_ADDRSTRLEN + 2];
	 char eth_addr[2][20];

	 inet_ntop4(ip_addr[0], INET_ADDRSTRLEN + 2, arp->spa._32, 0xFFFFFFFF);
	 // fprintf(fptr, "Source IP Address:      %s\n", ip_addr);

	 inet_ntop4(ip_addr[1], INET_ADDRSTRLEN + 2, arp->tpa._32, 0xFFFFFFFF);
	 // fprintf(fptr, "Destination IP Address: %s\n", ip_addr);

	 inet_mtoa(eth_addr[0], 20, (struct ether_addr *)&arp->sha);
	 // fprintf(fptr, "Source MAC Address:     %s\n", eth_addr);

	 inet_mtoa(eth_addr[1], 20, (struct ether_addr *)&arp->tha);
	 // fprintf(fptr, "Destination MAC Address:     %s\n", eth_addr);

	 fprintf(fptr, "%15s      ->      %-15s\n", ip_addr[0], ip_addr[1]);
	 fprintf(fptr, "%s    ->    %s\n", eth_addr[0], eth_addr[1]);
	 fprintf(fptr, "ARP Operation: %u\n", arp->op);

	 inet_mtoa(eth_addr[0], 20, (struct ether_addr *)&eth->s_addr);
	 inet_mtoa(eth_addr[1], 20, (struct ether_addr *)&eth->d_addr);
	 fprintf(fptr, "[%s]  ->  [%s]\n", eth_addr[0], eth_addr[1]);
	 fprintf(fptr, "Ether Type: %u\n", eth->ether_type);

	 fprintf(fptr, "\n");
}


/**************************************************************************//**
 *
 * pktgen_send_arp - Send an ARP request packet.
 *
 * DESCRIPTION
 * Create and send an ARP request packet.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
pktgen_send_arp(uint32_t pid, uint32_t type, uint8_t seq_idx)
{
	port_info_t	*info = &pktgen.info[pid];
	pkt_seq_t	  *pkt;
	struct rte_mbuf   *m;
	struct ether_hdr  *eth;
	arpPkt_t	   *arp;
	uint32_t addr;
	uint8_t qid = 0;

	#ifdef DEBUG
	FILE *fptr;

	fptr = fopen("/tmp/pktgen_custom.log", "a");
	#endif

	pkt = &info->seq_pkt[seq_idx];
	m   = rte_pktmbuf_alloc(info->q[qid].special_mp);
	if (unlikely(m == NULL) ) {
		 pktgen_log_warning("No packet buffers found");
		 return;
	}
	eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
	arp = (arpPkt_t *)&eth[1];

	/* src and dest addr */
	memset(&eth->d_addr, 0xFF, 6);
	ether_addr_copy(&pkt->eth_src_addr, &eth->s_addr);
	eth->ether_type = htons(ETHER_TYPE_ARP);

	memset(arp, 0, sizeof(arpPkt_t));

	rte_memcpy(&arp->sha, &pkt->eth_src_addr, 6);
	addr = htonl(pkt->ip_src_addr.addr.ipv4.s_addr);
	inetAddrCopy(&arp->spa, &addr);

	memset(&arp->tha, 0, 6);

	if (likely(type == GRATUITOUS_ARP) ) {
		 /* The destination IP == source IP fpr GARP. */
		 addr = htonl(pkt->ip_src_addr.addr.ipv4.s_addr);
		 inetAddrCopy(&arp->tpa, &addr);
	} else {
		 /* The destination IP is the IP of which the hw address is being probed. */
		 addr = htonl(pkt->ip_dst_addr.addr.ipv4.s_addr);
		 inetAddrCopy(&arp->tpa, &addr);
	}

	/* Fill in the rest of the ARP packet header */
	arp->hrd    = htons(ETH_HW_TYPE);
	arp->pro    = htons(ETHER_TYPE_IPv4);
	arp->hln    = 6;
	arp->pln    = 4;
	arp->op     = htons(ARP_REQUEST);

	m->pkt_len  = 60;
	m->data_len = 60;

	#ifdef DEBUG
	fprintf(fptr, "Sending %sARP request.  (type: %d)\n", type == GRATUITOUS_ARP ? "Gratuitous " : "", type);
	pktgen_dump_arp(fptr, arp, eth);
	fclose(fptr);
	#endif

	pktgen_send_mbuf(m, pid, qid);

	pktgen_set_q_flags(info, qid, DO_TX_FLUSH);
}

/**************************************************************************//**
 *
 * pktgen_process_arp - Handle a ARP request input packet and send a response.
 *
 * DESCRIPTION
 * Handle a ARP request input packet and send a response if required.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
pktgen_process_arp(struct rte_mbuf *m, uint32_t pid, uint32_t vlan)
{
	port_info_t   *info = &pktgen.info[pid];
	pkt_seq_t     *pkt;
	struct ether_hdr *eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
	arpPkt_t      *arp = (arpPkt_t *)&eth[1];

	#ifdef DEBUG
	FILE *fptr;

	fptr = fopen("/tmp/pktgen_custom.log", "a");
	#endif

	/* Adjust for a vlan header if present */
	if (vlan)
		 arp = (arpPkt_t *)((char *)arp + sizeof(struct vlan_hdr));

	/* Process all ARP requests if they are for us. */
	if (arp->op == htons(ARP_REQUEST) ) {
		 #ifdef DEBUG
		 fprintf(fptr, "Received an ARP request.");
		 #endif
		 if ((rte_atomic32_read(&info->port_flags) &
		      PROCESS_GARP_PKTS) &&
		     (arp->tpa._32 == arp->spa._32) ) {  /* Must be a GARP packet */
			  #ifdef DEBUG
			  fprintf(fptr, "GARP packet.");
			  #endif
			  pkt = pktgen_find_matching_ipdst(info, arp->spa._32);

			  /* Found a matching packet, replace the dst address */
			  if (pkt) {
				   rte_memcpy(&pkt->eth_dst_addr, &arp->sha, 6);
				   pktgen_set_q_flags(info,
					    get_txque(pktgen.l2p, rte_lcore_id(), pid), DO_TX_FLUSH);
				   pktgen_clear_display();

				   #ifdef DEBUG
				   fprintf(fptr, "Processing GARP\n");
				   pktgen_dump_arp(fptr, arp, eth);
				   fclose(fptr);
				   #endif
			  }
			  return;
		 }

		 pkt = pktgen_find_matching_ipsrc(info, arp->tpa._32);

		 /* ARP request not for this interface. */
		 if (likely(pkt != NULL) ) {
			  /* Grab the source MAC address as the destination address for the port. */
			  if (unlikely(pktgen.flags & MAC_FROM_ARP_FLAG) ) {
				   uint32_t i;

				   rte_memcpy(&pkt->eth_dst_addr, &arp->sha, 6);
				   for (i = 0; i < info->seqCnt; i++)
					    pktgen_packet_ctor(info, i, -1);
			  }

			  /* Swap the two MAC addresses */
			  ethAddrSwap(&arp->sha, &arp->tha);

			  /* Swap the two IP addresses */
			  inetAddrSwap(&arp->tpa._32, &arp->spa._32);

			  /* Set the packet to ARP reply */
			  arp->op = htons(ARP_REPLY);

			  /* Swap the MAC addresses */
			  ethAddrSwap(&eth->d_addr, &eth->s_addr);

			  /* Copy in the MAC address for the reply. */
			  rte_memcpy(&arp->sha, &pkt->eth_src_addr, 6);
			  rte_memcpy(&eth->s_addr, &pkt->eth_src_addr, 6);

			  pktgen_send_mbuf(m, pid, 0);

			  /* Flush all of the packets in the queue. */
			  pktgen_set_q_flags(info, 0, DO_TX_FLUSH);

			  /* No need to free mbuf as it was reused */
			  #ifdef DEBUG
			  fprintf(fptr, "Processing ARP request.\n");
			  pktgen_dump_arp(fptr, arp, eth);
			  fclose(fptr);
			  #endif
			  return;
		 }
	} else if (arp->op == htons(ARP_REPLY) ) {
		 pkt = pktgen_find_matching_ipsrc(info, arp->tpa._32);

		 #ifdef DEBUG
		 fprintf(fptr, "Processing ARP Reply.\n");
		 pktgen_dump_arp(fptr, arp, eth);
		 fclose(fptr);
		 #endif

		 /* ARP request not for this interface. */
		 if (likely(pkt != NULL) ) {
			  /* Grab the real destination MAC address */
			  if (pkt->ip_dst_addr.addr.ipv4.s_addr ==
			      ntohl(arp->spa._32) )
			  {
				   rte_memcpy(&pkt->eth_dst_addr, &arp->sha, 6);
			  }

			  pktgen.flags |= PRINT_LABELS_FLAG;
		 }
	}
}
