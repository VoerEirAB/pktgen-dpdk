/*-
 * Copyright (c) <2010-2017>, Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* Created 2010 by Keith Wiles @ intel.com */

#include <stdint.h>
#include <time.h>

#include "pktgen.h"
#include "pktgen-gre.h"
#include "pktgen-tcp.h"
#include "pktgen-ipv4.h"
#include "pktgen-ipv6.h"
#include "pktgen-udp.h"
#include "pktgen-arp.h"
#include "pktgen-vlan.h"
#include "pktgen-cpu.h"
#include "pktgen-display.h"
#include "pktgen-random.h"
#include "pktgen-log.h"
#include "pktgen-gtpu.h"
#include "pktgen-cfg.h"

#define PKTGEN_RETRY_COUNT	10000

/* Allocated the pktgen structure for global use */
pktgen_t pktgen;

/**************************************************************************//**
 *
 * pktgen_wire_size - Calculate the wire size of the data to be sent.
 *
 * DESCRIPTION
 * Calculate the number of bytes/bits in a burst of traffic.
 *
 * RETURNS: Number of bits in burst of packets.
 *
 * SEE ALSO:
 */

uint64_t
pktgen_wire_size(port_info_t *info)
{
	uint64_t i, size = 0;

	if (rte_atomic32_read(&info->port_flags) & SEND_PCAP_PKTS)
		size = info->pcap->pkt_size + PKT_PREAMBLE_SIZE +
			INTER_FRAME_GAP + ETHER_CRC_LEN;
	else {
		if (unlikely(info->seqCnt > 0)) {
			for (i = 0; i < info->seqCnt; i++)
				size += info->seq_pkt[i].pktSize +
					PKT_PREAMBLE_SIZE + INTER_FRAME_GAP +
					ETHER_CRC_LEN;
			size = size / info->seqCnt;	/* Calculate the average sized packet */
		} else
			size = info->seq_pkt[SINGLE_PKT].pktSize +
				PKT_PREAMBLE_SIZE + INTER_FRAME_GAP + ETHER_CRC_LEN;
	}
	return size;
}

/**************************************************************************//**
 *
 * pktgen_packet_rate_pps - Calculate the transmit rate from either the rate or
 * the pps value.
 *
 * DESCRIPTION
 * Calculate the number of cycles to wait between sending bursts of traffic,
 * from either the rate or the pps value.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
pktgen_packet_rate_pps(port_info_t *info)
{
	uint8_t tx_rate = info->tx_rate;
  if (tx_rate == 255)  // tx_rate was set to -1. Which implies, pps was set.
  {
    #ifdef DEBUG
      printf("**********************************pktgen_packet_rate_pps***********************************\n");
      printf("Calling `pktgen_packet_pps()`.  rate: %i\n", tx_rate);
      printf("*******************************************************************************************\n");
    #endif
    pktgen_packet_pps(info);
  }
  else
  {
    #ifdef DEBUG
      printf("**********************************pktgen_packet_rate_pps***********************************\n");
      printf("Calling `pktgen_packet_rate()`.  rate: %i\n", tx_rate);
      printf("*******************************************************************************************\n");
    #endif
    pktgen_packet_rate(info);
  }
}

/**************************************************************************//**
 *
 * pktgen_packet_rate - Calculate the transmit rate.
 *
 * DESCRIPTION
 * Calculate the number of cycles to wait between sending bursts of traffic.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
pktgen_packet_rate(port_info_t *info)
{
	uint64_t wire_size = (pktgen_wire_size(info) * 8);
	uint64_t link = (uint64_t)info->link.link_speed * Million;
	uint64_t pps = ((link / wire_size) * info->tx_rate) / 100;
	uint64_t cpp = (pps > 0) ? (pktgen.hz / pps) : (pktgen.hz / 4);

	info->tx_pps    = pps;
	info->tx_cycles = ((cpp * info->tx_burst) * get_port_txcnt(pktgen.l2p, info->pid));

  #ifdef DEBUG
    printf("**********************************pktgen_packet_rate***************************************\n");
    printf("wiresize: %lu\tlink: %lu\tpps: %lu\trate: %f\tcpp: %lu\n", wire_size, link, pps, info->tx_rate, cpp);
    printf("*******************************************************************************************\n");
  #endif
}

/**************************************************************************//**
 *
 * pktgen_packet_pps - Set the PPS to fix rate.
 *
 * DESCRIPTION
 * Calculate the number of cycles to wait between sending bursts of traffic.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
pktgen_packet_pps(port_info_t *info)
{
  uint64_t pps = info->tx_pps;
  uint8_t tx_rate = -1;   // disabling rate
  uint64_t cpp = (pps > 0) ? (pktgen.hz / pps) : (pktgen.hz / 4);

  info->tx_rate = tx_rate;
  info->tx_cycles = ((cpp * info->tx_burst) / get_port_txcnt(pktgen.l2p, info->pid));
  #ifdef DEBUG
    uint64_t wire_size = (pktgen_wire_size(info) * 8);
    uint64_t link = (uint64_t)info->link.link_speed * Million;
    printf("**********************************pktgen_packet_pps****************************************\n");
    printf("Setting values: wiresize: %lu\tlink: %lu\tcpp: %lu\t from pps: %lu\n", wire_size, link, cpp, pps);
    printf("*******************************************************************************************\n");
  #endif
}

/**************************************************************************//**
 *
 * pktgen_fill_pattern - Create the fill pattern in a packet buffer.
 *
 * DESCRIPTION
 * Create a fill pattern based on the arguments for the packet data.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static __inline__ void
pktgen_fill_pattern(uint8_t *p, uint32_t len, uint32_t type, char *user) {
	uint32_t i;

	switch (type) {
	case USER_FILL_PATTERN:
		memset(p, 0, len);
		for (i = 0; i < len; i++)
			p[i] = user[i & (USER_PATTERN_SIZE - 1)];
		break;

	case NO_FILL_PATTERN:
		break;

	case ZERO_FILL_PATTERN:
		memset(p, 0, len);
		break;

	default:
	case ABC_FILL_PATTERN:	/* Byte wide ASCII pattern */
		for (i = 0; i < len; i++)
			p[i] = "abcdefghijklmnopqrstuvwxyz012345"[i & 0x1f];
		break;
	}
}

/**************************************************************************//**
 *
 * pktgen_find_matching_ipsrc - Find the matching IP source address
 *
 * DESCRIPTION
 * locate and return the pkt_seq_t pointer to the match IP address.
 *
 * RETURNS: pkt_seq_t  * or NULL
 *
 * SEE ALSO:
 */

pkt_seq_t *
pktgen_find_matching_ipsrc(port_info_t *info, uint32_t addr)
{
	pkt_seq_t *pkt = NULL;
	int i;

	addr = ntohl(addr);

	/* Search the sequence packets for a match */
	for (i = 0; i < info->seqCnt; i++)
		if (addr == info->seq_pkt[i].ip_src_addr.addr.ipv4.s_addr) {
			pkt = &info->seq_pkt[i];
			break;
		}

	/* Now try to match the single packet address */
	if (pkt == NULL)
		if (addr == info->seq_pkt[SINGLE_PKT].ip_src_addr.addr.ipv4.s_addr)
			pkt = &info->seq_pkt[SINGLE_PKT];

	return pkt;
}

/**************************************************************************//**
 *
 * pktgen_find_matching_ipdst - Find the matching IP destination address
 *
 * DESCRIPTION
 * locate and return the pkt_seq_t pointer to the match IP address.
 *
 * RETURNS: pkt_seq_t  * or NULL
 *
 * SEE ALSO:
 */

pkt_seq_t *
pktgen_find_matching_ipdst(port_info_t *info, uint32_t addr)
{
	pkt_seq_t *pkt = NULL;
	int i;

	addr = ntohl(addr);

	/* Search the sequence packets for a match */
	for (i = 0; i < info->seqCnt; i++)
		if (addr == info->seq_pkt[i].ip_dst_addr.addr.ipv4.s_addr) {
			pkt = &info->seq_pkt[i];
			break;
		}

	/* Now try to match the single packet address */
	if (pkt == NULL)
		if (addr == info->seq_pkt[SINGLE_PKT].ip_dst_addr.addr.ipv4.s_addr)
			pkt = &info->seq_pkt[SINGLE_PKT];

	/* Now try to match the range packet address */
	if (pkt == NULL)
		if (addr == info->seq_pkt[RANGE_PKT].ip_dst_addr.addr.ipv4.s_addr)
			pkt = &info->seq_pkt[RANGE_PKT];

	return pkt;
}

static __inline__ latency_t *
pktgen_latency_pointer(port_info_t *info, struct rte_mbuf *m, int32_t seq_idx)
{
	latency_t *latency;
	char *p;

	p = rte_pktmbuf_mtod(m, char *);

	p += sizeof(struct ether_hdr);

	p += (info->seq_pkt[seq_idx].ethType == ETHER_TYPE_IPv4) ?
		sizeof(struct ipv4_hdr) : sizeof(struct ipv6_hdr);

	p += (info->seq_pkt[seq_idx].ipProto == IPPROTO_UDP) ?
		sizeof(struct udp_hdr) : sizeof(struct tcp_hdr);

	/* Force pointer to be aligned correctly */
	p = RTE_PTR_ALIGN_CEIL(p, sizeof(uint64_t));

	latency = (latency_t *)p;

	return latency;
}

static inline void
pktgen_latency_apply(port_info_t *info __rte_unused,
		     struct rte_mbuf **mbufs, int cnt, int32_t seq_idx)
{
	latency_t *latency;
	int i;

	for (i = 0; i < cnt; i++) {
		latency = pktgen_latency_pointer(info, mbufs[i], seq_idx);

		latency->timestamp  = rte_rdtsc_precise();
		latency->magic      = LATENCY_MAGIC;
	}
}

static inline void
pktgen_do_tx_tap(port_info_t *info, struct rte_mbuf **mbufs, int cnt)
{
	int i;

	for (i = 0; i < cnt; i++)
		if (write(info->tx_tapfd, rte_pktmbuf_mtod(mbufs[i], char *), mbufs[i]->pkt_len) < 0) {
			pktgen_log_error("Write failed for tx_tap%d", info->pid);
			break;
		}
}

/**************************************************************************//**
 *
 * _send_burst_fast - Send a burst of packet as fast as possible.
 *
 * DESCRIPTION
 * Transmit a burst of packets to a given port.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static __inline__ void
_send_burst_fast(port_info_t *info, uint16_t qid)
{
	struct mbuf_table   *mtab = &info->q[qid].tx_mbufs;
	struct rte_mbuf **pkts;
	uint32_t ret, cnt, retry;

	cnt = mtab->len;
	mtab->len = 0;

	pkts    = mtab->m_table;

	retry = PKTGEN_RETRY_COUNT;
	if (rte_atomic32_read(&info->port_flags) & PROCESS_TX_TAP_PKTS)
		while (cnt && retry) {
			ret = rte_eth_tx_burst(info->pid, qid, pkts, cnt);

			pktgen_do_tx_tap(info, pkts, ret);

			pkts += ret;
			cnt -= ret;
			if (!ret)
				retry--;
		}
	else
		while (cnt && retry) {
			ret = rte_eth_tx_burst(info->pid, qid, pkts, cnt);

			pkts += ret;
			cnt -= ret;
			if (!ret)
				retry--;
		}
}

/**************************************************************************//**
 *
 * _send_burst_random - Send a burst of packets with random bits.
 *
 * DESCRIPTION
 * Transmit a burst of packets to a given port.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static __inline__ void
_send_burst_random(port_info_t *info, uint16_t qid)
{
	struct mbuf_table   *mtab = &info->q[qid].tx_mbufs;
	struct rte_mbuf **pkts;
	uint32_t ret, cnt, flags, retry;

	cnt         = mtab->len;
	mtab->len   = 0;
	pkts        = mtab->m_table;

	retry = 100;

	flags   = rte_atomic32_read(&info->port_flags);
	if (unlikely(flags & PROCESS_TX_TAP_PKTS))
		while (cnt && retry) {
			pktgen_rnd_bits_apply(info, pkts, cnt, NULL);

			ret = rte_eth_tx_burst(info->pid, qid, pkts, cnt);

			pktgen_do_tx_tap(info, pkts, ret);

			pkts += ret;
			cnt -= ret;
			if (!ret)
				retry--;
		}
	else
		while (cnt && retry) {
			pktgen_rnd_bits_apply(info, pkts, cnt, NULL);

			ret = rte_eth_tx_burst(info->pid, qid, pkts, cnt);

			pkts += ret;
			cnt -= ret;
			if (!ret)
				retry--;
		}
}

/**************************************************************************//**
 *
 * _send_burst_latency - Send a burst of packets with latency time.
 *
 * DESCRIPTION
 * Transmit a burst of packets to a given port.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static __inline__ void
_send_burst_latency(port_info_t *info, uint16_t qid, int32_t seq_idx)
{
	struct mbuf_table   *mtab = &info->q[qid].tx_mbufs;
	struct rte_mbuf **pkts;
	uint32_t ret, cnt, retry;

	cnt         = mtab->len;
	mtab->len   = 0;
	pkts        = mtab->m_table;
	retry       = 100;
	while (cnt && retry) {
		pktgen_latency_apply(info, pkts, cnt, seq_idx);

		ret = rte_eth_tx_burst(info->pid, qid, pkts, cnt);

		pkts += ret;
		cnt -= ret;
		if (!ret)
			retry--;
	}
}

static __inline__ void
pktgen_send_burst(port_info_t *info, uint16_t qid)
{
	uint32_t flags;
	int32_t seq_idx;

	flags = rte_atomic32_read(&info->port_flags);

	if (flags & SEND_RANGE_PKTS)
		seq_idx = RANGE_PKT;
	else
		seq_idx = SINGLE_PKT;

	if (flags & SEND_LATENCY_PKTS)
		_send_burst_latency(info, qid, seq_idx);
	else if (flags & SEND_RANDOM_PKTS)
		_send_burst_random(info, qid);
	else
		_send_burst_fast(info, qid);
}

static __inline__ void
pktgen_recv_latency(port_info_t *info, struct rte_mbuf **pkts, uint16_t nb_pkts)
{
	uint32_t flags;
	uint64_t lat, jitter;
	int32_t seq_idx;

	flags = rte_atomic32_read(&info->port_flags);

	if (flags & SEND_RANGE_PKTS)
		seq_idx = RANGE_PKT;
	else
		seq_idx = SINGLE_PKT;

	if (flags & SEND_LATENCY_PKTS) {
		int i;
		latency_t *latency;

		for (i = 0; i < nb_pkts; i++) {
			latency = pktgen_latency_pointer(info, pkts[i], seq_idx);

			if (latency->magic == LATENCY_MAGIC) {
				lat = (rte_rdtsc_precise() - latency->timestamp);
				info->avg_latency += lat;
				if (lat > info->prev_latency)
					jitter = lat - info->prev_latency;
				else
					jitter = info->prev_latency - lat;
				if (jitter > info->jitter_threshold_clks)
					info->jitter_count++;
				info->prev_latency = lat;
			} else
			info->magic_errors++;
		}
		info->latency_nb_pkts += nb_pkts;
	}
}

/**************************************************************************//**
 *
 * pktgen_tx_flush - Flush Tx buffers from ring.
 *
 * DESCRIPTION
 * Flush TX buffers from ring.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static __inline__ void
pktgen_tx_flush(port_info_t *info, uint16_t qid)
{
	/* Flush any queued pkts to the driver. */
	pktgen_send_burst(info, qid);

#if RTE_VERSION >= RTE_VERSION_NUM(17, 5, 0, 0)
	rte_delay_ms(250);

	rte_eth_tx_done_cleanup(info->pid, qid, 0);
#endif

	pktgen_clr_q_flags(info, qid, DO_TX_FLUSH);
}

/**************************************************************************//**
 *
 * pktgen_exit_cleanup - Clean up the data and other items
 *
 * DESCRIPTION
 * Clean up the data.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static __inline__ void
pktgen_exit_cleanup(uint8_t lid)
{
	port_info_t *info;
	uint8_t idx, pid, qid;

	for (idx = 0; idx < get_lcore_txcnt(pktgen.l2p, lid); idx++) {
		pid = get_tx_pid(pktgen.l2p, lid, idx);
		if ( (info = (port_info_t *)get_port_private(pktgen.l2p, pid)) != NULL) {
			qid = get_txque(pktgen.l2p, lid, pid);
			pktgen_tx_flush(info, qid);
		}
	}
}

/**************************************************************************//**
 *
 * pktgen_has_work - Determine if lcore has work to do, if not wait for stop.
 *
 * DESCRIPTION
 * If lcore has work to do then return zero else spin till stopped and return 1.
 *
 * RETURNS: 0 or 1
 *
 * SEE ALSO:
 */

static __inline__ int
pktgen_has_work(void)
{
	if (!get_map(pktgen.l2p, RTE_MAX_ETHPORTS, rte_lcore_id())) {
		pktgen_log_warning("Nothing to do on lcore %d: exiting",
				   rte_lcore_id());
		return 1;
	}
	return 0;
}

/**************************************************************************//**
 *
 * pktgen_packet_ctor - Construct a complete packet with all headers and data.
 *
 * DESCRIPTION
 * Construct a packet type based on the arguments passed with all headers.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
pktgen_packet_ctor(port_info_t *info, int32_t seq_idx, int32_t type)
{
	pkt_seq_t         *pkt = &info->seq_pkt[seq_idx];
	struct ether_hdr  *eth = (struct ether_hdr *)&pkt->hdr.eth;
	char *l3_hdr = NULL;
	uint16_t tlen;

	/* Fill in the pattern for data space. */
	pktgen_fill_pattern((uint8_t *)&pkt->hdr,
			    (sizeof(pkt_hdr_t) + sizeof(pkt->pad)),
			    info->fill_pattern_type, info->user_pattern);

	/* Add GRE header and adjust ether_hdr pointer if requested */
	if (rte_atomic32_read(&info->port_flags) & SEND_GRE_IPv4_HEADER)
		l3_hdr = pktgen_gre_hdr_ctor(info, pkt, (greIp_t *)l3_hdr);
	else if (rte_atomic32_read(&info->port_flags) & SEND_GRE_ETHER_HEADER)
		l3_hdr = pktgen_gre_ether_hdr_ctor(info, pkt, (greEther_t *)l3_hdr);
	else
		l3_hdr = pktgen_ether_hdr_ctor(info, pkt, eth);

	if (likely(pkt->ethType == ETHER_TYPE_IPv4)) {
		if (likely(pkt->ipProto == PG_IPPROTO_TCP)) {
			if (pkt->dport != PG_IPPROTO_L4_GTPU_PORT) {
				/* Construct the TCP header */
				pktgen_tcp_hdr_ctor(pkt, l3_hdr, ETHER_TYPE_IPv4);

				/* IPv4 Header constructor */
				pktgen_ipv4_ctor(pkt, l3_hdr);
			} else {
				/* Construct the GTP-U header */
				pktgen_gtpu_hdr_ctor(pkt, l3_hdr, pkt->ipProto,
						GTPu_VERSION | GTPu_PT_FLAG, 0, 0, 0);

				/* Construct the TCP header */
				pktgen_tcp_hdr_ctor(pkt, l3_hdr, ETHER_TYPE_IPv4);

				/* IPv4 Header constructor */
				pktgen_ipv4_ctor(pkt, l3_hdr);
			}
		} else if (pkt->ipProto == PG_IPPROTO_UDP) {
			if (pkt->dport != PG_IPPROTO_L4_GTPU_PORT) {
				/* Construct the UDP header */
				pktgen_udp_hdr_ctor(pkt, l3_hdr, ETHER_TYPE_IPv4);

				/* IPv4 Header constructor */
				pktgen_ipv4_ctor(pkt, l3_hdr);
			} else {
				/* Construct the GTP-U header */
				pktgen_gtpu_hdr_ctor(pkt, l3_hdr, pkt->ipProto,
						GTPu_VERSION | GTPu_PT_FLAG, 0, 0, 0);

				/* Construct the UDP header */
				pktgen_udp_hdr_ctor(pkt, l3_hdr, ETHER_TYPE_IPv4);

				/* IPv4 Header constructor */
				pktgen_ipv4_ctor(pkt, l3_hdr);
			}
		} else if (pkt->ipProto == PG_IPPROTO_ICMP) {
			udpip_t           *uip;
			icmpv4Hdr_t       *icmp;

			/* Start from Ethernet header */
			uip = (udpip_t *)l3_hdr;

			/* Create the ICMP header */
			uip->ip.src         = htonl(pkt->ip_src_addr.addr.ipv4.s_addr);
			uip->ip.dst         = htonl(pkt->ip_dst_addr.addr.ipv4.s_addr);
			tlen                = pkt->pktSize - (pkt->ether_hdr_size + sizeof(ipHdr_t));
			uip->ip.len         = htons(tlen);
			uip->ip.proto       = pkt->ipProto;

			icmp = (icmpv4Hdr_t *)&uip->udp;
			icmp->code                      = 0;
			if ( (type == -1) || (type == ICMP4_TIMESTAMP)) {
				icmp->type                      =
					ICMP4_TIMESTAMP;
				icmp->data.timestamp.ident      = 0x1234;
				icmp->data.timestamp.seq        = 0x5678;
				icmp->data.timestamp.originate  = 0x80004321;
				icmp->data.timestamp.receive    = 0;
				icmp->data.timestamp.transmit   = 0;
			} else if (type == ICMP4_ECHO) {
				icmp->type                      = ICMP4_ECHO;
				icmp->data.echo.ident           = 0x1234;
				icmp->data.echo.seq             = 0x5678;
				icmp->data.echo.data            = 0;
			}
			icmp->cksum     = 0;
			/* ICMP4_TIMESTAMP_SIZE */
			tlen            = pkt->pktSize - (pkt->ether_hdr_size + sizeof(ipHdr_t));
			icmp->cksum     = cksum(icmp, tlen, 0);
			if (icmp->cksum == 0)
				icmp->cksum = 0xFFFF;

			/* IPv4 Header constructor */
			pktgen_ipv4_ctor(pkt, l3_hdr);
		}
	} else if (pkt->ethType == ETHER_TYPE_IPv6) {
		if (pkt->ipProto == PG_IPPROTO_TCP) {
			/* Construct the TCP header */
			pktgen_tcp_hdr_ctor(pkt, l3_hdr, ETHER_TYPE_IPv6);

			/* IPv6 Header constructor */
			pktgen_ipv6_ctor(pkt, l3_hdr);
		} else if (pkt->ipProto == PG_IPPROTO_UDP) {
			/* Construct the UDP header */
			pktgen_udp_hdr_ctor(pkt, l3_hdr, ETHER_TYPE_IPv6);

			/* IPv6 Header constructor */
			pktgen_ipv6_ctor(pkt, l3_hdr);
		}
	} else if (pkt->ethType == ETHER_TYPE_ARP) {
		/* Start from Ethernet header */
		arpPkt_t *arp = (arpPkt_t *)l3_hdr;

		arp->hrd = htons(1);
		arp->pro = htons(ETHER_TYPE_IPv4);
		arp->hln = ETHER_ADDR_LEN;
		arp->pln = 4;

		/* FIXME make request/reply operation selectable by user */
		arp->op  = htons(2);

		ether_addr_copy(&pkt->eth_src_addr,
				(struct ether_addr *)&arp->sha);
		arp->spa._32 = htonl(pkt->ip_src_addr.addr.ipv4.s_addr);

		ether_addr_copy(&pkt->eth_dst_addr,
				(struct ether_addr *)&arp->tha);
		arp->tpa._32 = htonl(pkt->ip_dst_addr.addr.ipv4.s_addr);
	} else
		pktgen_log_error("Unknown EtherType 0x%04x", pkt->ethType);
}

/**************************************************************************//**
 *
 * pktgen_send_mbuf - Send a single packet to the given port.
 *
 * DESCRIPTION
 * Send a single packet to a given port, but enqueue the packet until we have
 * a given burst count of packets to send.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
pktgen_send_mbuf(struct rte_mbuf *m, uint8_t pid, uint16_t qid)
{
	port_info_t *info = &pktgen.info[pid];
	struct mbuf_table   *mtab = &info->q[qid].tx_mbufs;

	/* Add packet to the TX list. */
	mtab->m_table[mtab->len++] = m;

	/* Fill our tx burst requirement */
	if (mtab->len >= info->tx_burst)
		pktgen_send_burst(info, qid);
}

/**************************************************************************//**
 *
 * pktgen_packet_type - Examine a packet and return the type of packet
 *
 * DESCRIPTION
 * Examine a packet and return the type of packet.
 * the packet.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static __inline__ pktType_e
pktgen_packet_type(struct rte_mbuf *m)
{
	pktType_e ret;
	struct ether_hdr *eth;

	eth = rte_pktmbuf_mtod(m, struct ether_hdr *);

	ret = ntohs(eth->ether_type);

	return ret;
}

/**************************************************************************//**
 *
 * pktgen_packet_classify - Examine a packet and classify it for statistics
 *
 * DESCRIPTION
 * Examine a packet and determine its type along with counting statistics around
 * the packet.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static void
pktgen_packet_classify(struct rte_mbuf *m, int pid)
{
	port_info_t *info = &pktgen.info[pid];
	uint32_t plen;
	uint32_t flags;
	pktType_e pType;

	pType = pktgen_packet_type(m);

#ifdef RTE_DBUF_INDIRECT
	if (RTE_DBUF_INDIRECT(m)) {
		struct rte_dbuf *d = rte_dbuf_from_indirect(m->buf_addr);
		plen = rte_pktdbuf_data_len(d);
	} else
#endif
		plen = rte_pktmbuf_pkt_len(m);

	flags = rte_atomic32_read(&info->port_flags);
	if (unlikely(flags & (PROCESS_INPUT_PKTS | PROCESS_RX_TAP_PKTS))) {
		if (unlikely(flags & PROCESS_RX_TAP_PKTS))
			if (write(info->rx_tapfd, rte_pktmbuf_mtod(m, char *),
				  m->pkt_len) < 0)
				pktgen_log_error("Write failed for rx_tap%d",
						 pid);

		switch ((int)pType) {
		case ETHER_TYPE_ARP:    info->stats.arp_pkts++;
			pktgen_process_arp(m, pid, 0);     break;
		case ETHER_TYPE_IPv4:   info->stats.ip_pkts++;
			pktgen_process_ping4(m, pid, 0);   break;
		case ETHER_TYPE_IPv6:   info->stats.ipv6_pkts++;
			pktgen_process_ping6(m, pid, 0);   break;
		case ETHER_TYPE_VLAN:   info->stats.vlan_pkts++;
			pktgen_process_vlan(m, pid);       break;
		case UNKNOWN_PACKET:	/* FALL THRU */
		default:                break;
		}
	} else
		/* Count the type of packets found. */
		switch ((int)pType) {
		case ETHER_TYPE_ARP:        info->stats.arp_pkts++;     break;
		case ETHER_TYPE_IPv4:       info->stats.ip_pkts++;      break;
		case ETHER_TYPE_IPv6:       info->stats.ipv6_pkts++;    break;
		case ETHER_TYPE_VLAN:       info->stats.vlan_pkts++;    break;
		default:                    break;
		}

	plen += pktgen_get_hw_strip_crc();

	/* Count the size of each packet. */
	if (plen == ETHER_MIN_LEN)
		info->sizes._64++;
	else if ( (plen >= (ETHER_MIN_LEN + 1)) && (plen <= 127))
		info->sizes._65_127++;
	else if ( (plen >= 128) && (plen <= 255))
		info->sizes._128_255++;
	else if ( (plen >= 256) && (plen <= 511))
		info->sizes._256_511++;
	else if ( (plen >= 512) && (plen <= 1023))
		info->sizes._512_1023++;
	else if ( (plen >= 1024) && (plen <= ETHER_MAX_LEN))
		info->sizes._1024_1518++;
	else if (plen < ETHER_MIN_LEN) {
		info->sizes.runt++;
	} else if (plen > ETHER_MAX_LEN)
		info->sizes.jumbo++;

	/* Process multicast and broadcast packets. */
	if (unlikely(((uint8_t *)m->buf_addr + m->data_off)[0] == 0xFF)) {
		if ( (((uint64_t *)m->buf_addr + m->data_off)[0] &
		      0xFFFFFFFFFFFF0000LL) == 0xFFFFFFFFFFFF0000LL)
			info->sizes.broadcast++;
		else if ( ((uint8_t *)m->buf_addr + m->data_off)[0] & 1)
			info->sizes.multicast++;
	}
}

/**************************************************************************//**
 *
 * pktgen_packet_classify_buld - Classify a set of packets in one call.
 *
 * DESCRIPTION
 * Classify a list of packets and to improve classify performance.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

#define PREFETCH_OFFSET     3
static __inline__ void
pktgen_packet_classify_bulk(struct rte_mbuf **pkts, int nb_rx, int pid)
{
	int j, i;

	/* Prefetch first packets */
	for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++)
		rte_prefetch0(rte_pktmbuf_mtod(pkts[j], void *));

	/* Prefetch and handle already prefetched packets */
	for (i = 0; i < (nb_rx - PREFETCH_OFFSET); i++) {
		rte_prefetch0(rte_pktmbuf_mtod(pkts[j], void *));
		j++;

		pktgen_packet_classify(pkts[i], pid);
	}

	/* Handle remaining prefetched packets */
	for (; i < nb_rx; i++)
		pktgen_packet_classify(pkts[i], pid);
}

/**************************************************************************//**
 *
 * pktgen_send_special - Send a special packet to the given port.
 *
 * DESCRIPTION
 * Create a special packet in the buffer provided.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static void
pktgen_send_special(port_info_t *info, uint32_t flags)
{
	uint32_t s;

	/* Send packets attached to the sequence packets. */
	for (s = 0; s < info->seqCnt; s++) {
		if (flags & SEND_GRATUITOUS_ARP)
			pktgen_send_arp(info->pid, GRATUITOUS_ARP, s);
		if (flags & SEND_ARP_REQUEST)
			pktgen_send_arp(info->pid, 0, s);

		if (flags & SEND_PING4_REQUEST)
			pktgen_send_ping4(info->pid, s);
#ifdef INCLUDE_PING6
		if (flags & SEND_PING6_REQUEST)
			pktgen_send_ping6(info->pid, s);
#endif
	}

	/* Send the requests from the Single packet setup. */
	if (flags & SEND_GRATUITOUS_ARP)
		pktgen_send_arp(info->pid, GRATUITOUS_ARP, SINGLE_PKT);
	if (flags & SEND_ARP_REQUEST)
		pktgen_send_arp(info->pid, 0, SINGLE_PKT);

	if (flags & SEND_PING4_REQUEST)
		pktgen_send_ping4(info->pid, SINGLE_PKT);
#ifdef INCLUDE_PING6
	if (flags & SEND_PING6_REQUEST)
		pktgen_send_ping6(info->pid, SINGLE_PKT);
#endif

	pktgen_clr_port_flags(info, SEND_ARP_PING_REQUESTS);
}

typedef struct {
	port_info_t *info;
	uint16_t qid;
} pkt_data_t;

static __inline__ void
pktgen_setup_cb(struct rte_mempool *mp,
		void *opaque, void *obj, unsigned obj_idx __rte_unused)
{
	pkt_data_t *data = (pkt_data_t *)opaque;
	struct rte_mbuf *m = (struct rte_mbuf *)obj;
	port_info_t *info;
	pkt_seq_t *pkt;
	uint16_t qid;

	info = data->info;
	qid = data->qid;

	/* Cleanup the mbuf data as virtio messes with the values */
	pktmbuf_reset(m);

	if (mp == info->q[qid].tx_mp)
		pkt = &info->seq_pkt[SINGLE_PKT];
	else if (mp == info->q[qid].range_mp)
		pkt = &info->seq_pkt[RANGE_PKT];
	else if (mp == info->q[qid].seq_mp)
		pkt = &info->seq_pkt[info->seqIdx];
	else
		pkt = NULL;

	/* allocate each mbuf and put them on a list to be freed. */
	if (mp == info->q[qid].tx_mp) {
		pktgen_packet_ctor(info, SINGLE_PKT, -1);

		rte_memcpy((uint8_t *)m->buf_addr + m->data_off,
			   (uint8_t *)&pkt->hdr, MAX_PKT_SIZE);

		m->pkt_len  = pkt->pktSize;
		m->data_len = pkt->pktSize;
	} else if (mp == info->q[qid].range_mp) {
		pktgen_range_ctor(&info->range, pkt);
		pktgen_packet_ctor(info, RANGE_PKT, -1);

		rte_memcpy((uint8_t *)m->buf_addr + m->data_off,
			   (uint8_t *)&pkt->hdr, MAX_PKT_SIZE);

		m->pkt_len  = pkt->pktSize;
		m->data_len = pkt->pktSize;
	} else if (mp == info->q[qid].seq_mp) {
		if (pktgen.is_gui_running)
			while (info->seqIdx < info->seqCnt) {
				pkt = &info->seq_pkt[info->seqIdx];

				/* Check the sequence and start from the beginning */
				if (++info->seqIdx >= info->seqCnt)
					info->seqIdx = 0;

				if (pkt->seq_enabled) {
					/* Call ctor for those sequence which are enabled in the GUI */
					pktgen_packet_ctor(info, info->seqIdx, -1);

					rte_memcpy((uint8_t *)m->buf_addr + m->data_off,
						   (uint8_t *)&pkt->hdr, MAX_PKT_SIZE);
					m->pkt_len  = pkt->pktSize;
					m->data_len = pkt->pktSize;
					pkt = &info->seq_pkt[info->seqIdx];
					break;
				}
			}
		else {
			pkt = &info->seq_pkt[info->seqIdx];
			pktgen_packet_ctor(info, info->seqIdx, -1);

			rte_memcpy((uint8_t *)m->buf_addr + m->data_off,
				   (uint8_t *)&pkt->hdr, MAX_PKT_SIZE);

			m->pkt_len  = pkt->pktSize;
			m->data_len = pkt->pktSize;

			pkt = &info->seq_pkt[info->seqIdx];

			/* move to the next packet in the sequence. */
			if (unlikely(++info->seqIdx >= info->seqCnt))
				info->seqIdx = 0;
		}
	}
}

/**************************************************************************//**
 *
 * pktgen_setup_packets - Setup the default packets to be sent.
 *
 * DESCRIPTION
 * Construct the default set of packets for a given port.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static __inline__ void
pktgen_setup_packets(port_info_t *info, struct rte_mempool *mp, uint16_t qid)
{
	pkt_data_t pkt_data;

	pktgen_clr_q_flags(info, qid, CLEAR_FAST_ALLOC_FLAG);

	if (mp == info->q[qid].pcap_mp)
		return;

	rte_spinlock_lock(&info->port_lock);

	pkt_data.info = info;
	pkt_data.qid = qid;

#if RTE_VERSION >= RTE_VERSION_NUM(16, 7, 0, 0)
	rte_mempool_obj_iter(mp, pktgen_setup_cb, &pkt_data);
#else
	{
		struct rte_mbuf *m, *mm;

		mm  = NULL;

		/* allocate each mbuf and put them on a list to be freed. */
		for (;; ) {
			if ((m = rte_pktmbuf_alloc(mp)) == NULL)
				break;

			/* Put the allocated mbuf into a list to be freed later */
			m->next = mm;
			mm = m;

			pktgen_setup_cb(mp, &pkt_data, m, 0);
		}
		if (mm != NULL)
			rte_pktmbuf_free(mm);
	}
#endif
	rte_spinlock_unlock(&info->port_lock);
}

/**************************************************************************//**
 *
 * pktgen_send_pkts - Send a set of packet buffers to a given port.
 *
 * DESCRIPTION
 * Transmit a set of packets mbufs to a given port.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static __inline__ void
pktgen_send_pkts(port_info_t *info, uint16_t qid, struct rte_mempool *mp)
{
	uint32_t flags;
	int rc = 0;

	flags = rte_atomic32_read(&info->port_flags);

	if (flags & SEND_FOREVER) {
		rc = pg_pktmbuf_alloc_bulk(mp,
					   info->q[qid].tx_mbufs.m_table,
					   info->tx_burst);
		if (rc == 0) {
			info->q[qid].tx_mbufs.len = info->tx_burst;
			info->q[qid].tx_cnt += info->tx_burst;

			pktgen_send_burst(info, qid);
		}
	} else {
		int64_t txCnt;

		txCnt = pkt_atomic64_tx_count(&info->current_tx_count, info->tx_burst);
		if (txCnt > 0) {
			rc = pg_pktmbuf_alloc_bulk(mp,
						   info->q[qid].tx_mbufs.m_table,
						   txCnt);
			if (rc == 0) {
				info->q[qid].tx_mbufs.len = txCnt;
				pktgen_send_burst(info, qid);
			}
		} else
			pktgen_clr_port_flags(info, (SENDING_PACKETS | SEND_FOREVER));
	}
}

/**************************************************************************//**
 *
 * pktgen_main_transmit - Determine the next packet format to transmit.
 *
 * DESCRIPTION
 * Determine the next packet format to transmit for a given port.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static __inline__ void
pktgen_main_transmit(port_info_t *info, uint16_t qid)
{
	struct rte_mempool *mp = NULL;
	uint32_t flags;

	flags = rte_atomic32_read(&info->port_flags);

	/*
	 * Transmit ARP/Ping packets if needed
	 */
	if ((flags & SEND_ARP_PING_REQUESTS))
		pktgen_send_special(info, flags);

	/* When not transmitting on this port then continue. */
	if (flags & SENDING_PACKETS) {
		mp = info->q[qid].tx_mp;

		if (flags & (SEND_RANGE_PKTS | SEND_PCAP_PKTS | SEND_SEQ_PKTS)) {
			if (flags & SEND_RANGE_PKTS)
				mp = info->q[qid].range_mp;
			else if (flags & SEND_SEQ_PKTS)
				mp = info->q[qid].seq_mp;
			else if (flags & SEND_PCAP_PKTS)
				mp = info->q[qid].pcap_mp;
		}

		if (rte_atomic32_read(&info->q[qid].flags) & CLEAR_FAST_ALLOC_FLAG)
			pktgen_setup_packets(info, mp, qid);

		pktgen_send_pkts(info, qid, mp);
	}

	flags = rte_atomic32_read(&info->q[qid].flags);
	if (flags & DO_TX_FLUSH)
		pktgen_tx_flush(info, qid);
}

/**************************************************************************//**
 *
 * pktgen_main_receive - Main receive routine for packets of a port.
 *
 * DESCRIPTION
 * Handle the main receive set of packets on a given port plus handle all of the
 * input processing if required.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static __inline__ void
pktgen_main_receive(port_info_t *info,
		    uint8_t lid,
		    struct rte_mbuf *pkts_burst[])
{
	uint8_t pid;
	uint16_t qid, nb_rx;
	capture_t *capture;

	pid = info->pid;
	qid = get_rxque(pktgen.l2p, lid, pid);

	/*
	 * Read packet from RX queues and free the mbufs
	 */
	if ( (nb_rx = rte_eth_rx_burst(pid, qid, pkts_burst, info->tx_burst)) == 0)
		return;

	info->q[qid].rx_cnt += nb_rx;

	pktgen_recv_latency(info, pkts_burst, nb_rx);

	/* packets are not freed in the next call. */
	pktgen_packet_classify_bulk(pkts_burst, nb_rx, pid);

	if (unlikely(info->dump_count > 0))
		pktgen_packet_dump_bulk(pkts_burst, nb_rx, pid);

	if (unlikely(rte_atomic32_read(&info->port_flags) & CAPTURE_PKTS)) {
		capture = &pktgen.capture[pktgen.core_info[lid].s.socket_id];
		if (unlikely((capture->port == pid) &&
			     (capture->lcore == lid)))
			pktgen_packet_capture_bulk(pkts_burst, nb_rx, capture);
	}

	rte_pktmbuf_free_bulk(pkts_burst, nb_rx);
}

static void
port_map_info(uint8_t lid, port_info_t **infos, uint8_t *qids,
	      uint8_t *txcnt, uint8_t *rxcnt, const char *msg)
{
	uint8_t idx, pid, cnt = 0;
	uint8_t rx, tx;
	char buf[256];

	rx = get_lcore_rxcnt(pktgen.l2p, lid);
	tx = get_lcore_txcnt(pktgen.l2p, lid);

	if (txcnt && rxcnt) {
		*rxcnt = rx;
		*txcnt = tx;
		cnt = tx;
	} else if (rxcnt) {
		*rxcnt = rx;
		cnt = rx;
	} else if (txcnt) {
		*txcnt = tx;
		cnt = tx;
	}

	snprintf(buf, sizeof(buf), "  %s processing lcore: %3d rx: %2d tx: %2d",
		 msg, lid, rx, tx);

	for (idx = 0; idx < cnt; idx++) {
		if (rxcnt)
			pid = get_rx_pid(pktgen.l2p, lid, idx);
		else
			pid = get_tx_pid(pktgen.l2p, lid, idx);

		if ((infos[idx] = get_port_private(pktgen.l2p, pid)) == NULL)
			rte_panic("Config error: No port %d found at %d lcore\n", pid, lid);

		if (qids)
			qids[idx] = get_txque(pktgen.l2p, lid, pid);
	}

	pktgen_log_info("%s", buf);
}

/**************************************************************************//**
 *
 * pktgen_main_rxtx_loop - Single thread loop for tx/rx packets
 *
 * DESCRIPTION
 * Handle sending and receiving packets from a given set of ports. This is the
 * main loop or thread started on a single core.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static void
pktgen_main_rxtx_loop(uint8_t lid)
{
	struct rte_mbuf *pkts_burst[DEFAULT_PKT_BURST];
	port_info_t   *infos[RTE_MAX_ETHPORTS];
	uint8_t qids[RTE_MAX_ETHPORTS];
	uint8_t idx, txcnt, rxcnt;
	uint64_t curr_tsc;
	uint64_t tx_next_cycle;	/**< Next cycle to send a burst of traffic */
	uint64_t tx_bond_cycle;
	uint32_t flags;

	memset(infos, '\0', sizeof(infos));
	memset(qids, '\0', sizeof(qids));

	port_map_info(lid, infos, qids, &txcnt, &rxcnt, "RX/TX");

	tx_next_cycle = rte_get_tsc_cycles() + infos[0]->tx_cycles;
	tx_bond_cycle = rte_get_tsc_cycles() + rte_get_timer_hz()/10;

	pg_start_lcore(pktgen.l2p, lid);

	if (rxcnt == 0)
		rte_panic("No ports found for %d lcore\n", lid);

	printf("For RX found %d port(s) for lcore %d\n", rxcnt, lid);
	for(idx = 0; idx < rxcnt; idx++) {
		if (infos[idx] == NULL)
			rte_panic("Invalid RX config: port at index %d not found for %d lcore\n", idx, lid);
	}

	if (txcnt == 0)
		rte_panic("No ports found for %d lcore\n", lid);

	printf("For TX found %d port(s) for lcore %d\n", txcnt, lid);
	for(idx = 0; idx < txcnt; idx++) {
		if (infos[idx] == NULL)
			rte_panic("Invalid TX config: port at index %d not found for %d lcore\n", idx, lid);
	}

	while (pg_lcore_is_running(pktgen.l2p, lid)) {
		for (idx = 0; idx < rxcnt; idx++)	/* Read Packets */
			pktgen_main_receive(infos[idx], lid, pkts_burst);

		curr_tsc = rte_get_tsc_cycles();

		/* Determine when is the next time to send packets */
		if (curr_tsc >= tx_next_cycle) {
			tx_next_cycle = curr_tsc + infos[0]->tx_cycles;

			for (idx = 0; idx < txcnt; idx++)	/* Transmit packets */
				pktgen_main_transmit(infos[idx], qids[idx]);
		} else if (curr_tsc >= tx_bond_cycle) {
			tx_bond_cycle = curr_tsc + rte_get_timer_hz()/10;
			for (idx = 0; idx < txcnt; idx++) {	/* Transmit zero pkts for Bonding PMD */
				flags = rte_atomic32_read(&infos[idx]->port_flags);
				if (flags & BONDING_TX_PACKETS) {
					rte_eth_tx_burst(infos[idx]->pid, qids[idx], NULL, 0);
				}
			}
		}
	}

	pktgen_log_debug("Exit %d", lid);

	pktgen_exit_cleanup(lid);
}

/**************************************************************************//**
 *
 * pktgen_main_tx_loop - Main transmit loop for a core, no receive packet handling
 *
 * DESCRIPTION
 * When Tx and Rx are split across two cores this routing handles the tx packets.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static void
pktgen_main_tx_loop(uint8_t lid)
{
	uint8_t idx, txcnt;
	port_info_t *infos[RTE_MAX_ETHPORTS];
	uint8_t qids[RTE_MAX_ETHPORTS];
	uint64_t curr_tsc;
	uint64_t tx_next_cycle;	/**< Next cycle to send a burst of traffic */
	uint64_t tx_bond_cycle;
	uint32_t flags;

	memset(infos, '\0', sizeof(infos));
	memset(qids, '\0', sizeof(qids));
	port_map_info(lid, infos, qids, &txcnt, NULL, "TX");

	tx_next_cycle = rte_get_tsc_cycles() + infos[0]->tx_cycles;
	tx_bond_cycle = rte_get_tsc_cycles() + rte_get_timer_hz()/10;

	pg_start_lcore(pktgen.l2p, lid);

	if (txcnt == 0)
		rte_panic("No ports found for %d lcore\n", lid);

	printf("For TX found %d port(s) for lcore %d\n", txcnt, lid);
	for(idx = 0;idx < txcnt; idx++) {
		if (infos[idx] == NULL)
			rte_panic("Invalid TX config: port at index %d not found for %d lcore\n", idx, lid);
	}

	idx = 0;
	while (pg_lcore_is_running(pktgen.l2p, lid)) {
		curr_tsc = rte_get_tsc_cycles();

		/* Determine when is the next time to send packets */
		if (curr_tsc >= tx_next_cycle) {
			tx_next_cycle = curr_tsc + infos[0]->tx_cycles;

			for (idx = 0; idx < txcnt; idx++)	/* Transmit packets */
				pktgen_main_transmit(infos[idx], qids[idx]);
		} else if (curr_tsc >= tx_bond_cycle) {
			tx_bond_cycle = curr_tsc + rte_get_timer_hz()/10;
			for (idx = 0; idx < txcnt; idx++) {	/* Transmit zero pkts for Bonding PMD */
				flags = rte_atomic32_read(&infos[idx]->port_flags);
				if (flags & BONDING_TX_PACKETS) {
					rte_eth_tx_burst(infos[idx]->pid, qids[idx], NULL, 0);
				}
			}
		}
	}

	pktgen_log_debug("Exit %d", lid);

	pktgen_exit_cleanup(lid);
}

/**************************************************************************//**
 *
 * pktgen_main_rx_loop - Handle only the rx packets for a set of ports.
 *
 * DESCRIPTION
 * When Tx and Rx processing is split between two ports this routine handles
 * only the receive packets.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static void
pktgen_main_rx_loop(uint8_t lid)
{
	struct rte_mbuf *pkts_burst[DEFAULT_PKT_BURST];
	uint8_t idx, rxcnt;
	port_info_t   *infos[RTE_MAX_ETHPORTS];

	memset(infos, '\0', sizeof(infos));
	port_map_info(lid, infos, NULL, NULL, &rxcnt, "RX");

	pg_start_lcore(pktgen.l2p, lid);

	if (rxcnt == 0)
		rte_panic("No ports found for %d lcore\n", lid);

	printf("For RX found %d port(s) for lcore %d\n", rxcnt, lid);
	for(idx = 0; idx < rxcnt; idx++) {
		if (infos[idx] == NULL)
			rte_panic("Invalid RX config: port at index %d not found for %d lcore\n", idx, lid);
	}

	while (pg_lcore_is_running(pktgen.l2p, lid))
		for (idx = 0; idx < rxcnt; idx++)	/* Read packet */
			pktgen_main_receive(infos[idx], lid, pkts_burst);

	pktgen_log_debug("Exit %d", lid);

	pktgen_exit_cleanup(lid);
}

/**************************************************************************//**
 *
 * pktgen_launch_one_lcore - Launch a single logical core thread.
 *
 * DESCRIPTION
 * Help launch a single thread on one logical core.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

int
pktgen_launch_one_lcore(void *arg __rte_unused)
{
	uint8_t lid = rte_lcore_id();

	if (pktgen_has_work())
		return 0;

	rte_delay_ms((lid + 1) * 21);

	switch (get_type(pktgen.l2p, lid)) {
	case RX_TYPE:               pktgen_main_rx_loop(lid);       break;
	case TX_TYPE:               pktgen_main_tx_loop(lid);       break;
	case (RX_TYPE | TX_TYPE):   pktgen_main_rxtx_loop(lid);     break;
	}
	return 0;
}

static void
_page_display(void)
{
	static unsigned int counter = 0;

	pktgen_display_set_color("top.spinner");
	scrn_printf(1, 1, "%c", "-\\|/"[(counter++ & 3)]);
	pktgen_display_set_color(NULL);

	if (pktgen.flags & CPU_PAGE_FLAG)
		pktgen_page_cpu();
	else if (pktgen.flags & PCAP_PAGE_FLAG)
		pktgen_page_pcap(pktgen.portNum);
	else if (pktgen.flags & RANGE_PAGE_FLAG)
		pktgen_page_range();
	else if (pktgen.flags & CONFIG_PAGE_FLAG)
		pktgen_page_config();
	else if (pktgen.flags & SEQUENCE_PAGE_FLAG)
		pktgen_page_seq(pktgen.portNum);
	else if (pktgen.flags & RND_BITFIELD_PAGE_FLAG)
		pktgen_page_random_bitfields(pktgen.flags & PRINT_LABELS_FLAG,
					     pktgen.portNum,
					     pktgen.info[pktgen.portNum].rnd_bitfields);
	else if (pktgen.flags & LOG_PAGE_FLAG)
		pktgen_page_log(pktgen.flags & PRINT_LABELS_FLAG);
	else if (pktgen.flags & LATENCY_PAGE_FLAG)
		pktgen_page_latency();
	else if (pktgen.flags & STATS_PAGE_FLAG)
		pktgen_page_phys_stats();
	else
		pktgen_page_stats();
}

/**************************************************************************//**
 *
 * pktgen_page_display - Display the correct page based on timer0 callback.
 *
 * DESCRIPTION
 * When timer0 is active update or display the correct page of data.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
pktgen_page_display(struct rte_timer *tim __rte_unused, void *arg __rte_unused)
{
	static unsigned int update_display = 1;

	/* Leave if the screen is paused */
	if (scrn_is_paused())
		return;

	scrn_save();

	if (pktgen.flags & UPDATE_DISPLAY_FLAG) {
		pktgen.flags &= ~UPDATE_DISPLAY_FLAG;
		update_display = 1;
	}

	update_display--;
	if (update_display == 0) {
		update_display = UPDATE_DISPLAY_TICK_INTERVAL;
		_page_display();

		if (pktgen.flags & PRINT_LABELS_FLAG)
			pktgen.flags &= ~PRINT_LABELS_FLAG;
	}

	scrn_restore();

	pktgen_print_packet_dump();
}

static struct rte_timer timer0;
static struct rte_timer timer1;

/**************************************************************************//**
 *
 * pktgen_timer_setup - Set up the timer callback routines.
 *
 * DESCRIPTION
 * Setup the two timers to be used for display and calculating statistics.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
rte_timer_setup(void)
{
	int lcore_id = rte_get_master_lcore();

	/* init RTE timer library */
	rte_timer_subsystem_init();

	/* init timer structures */
	rte_timer_init(&timer0);
	rte_timer_init(&timer1);

	/* load timer0, every 1/2 seconds, on Display lcore, reloaded automatically */
	rte_timer_reset(&timer0,
			UPDATE_DISPLAY_TICK_RATE,
			PERIODICAL,
			lcore_id,
			pktgen_page_display,
			NULL);

	/* load timer1, every second, on timer lcore, reloaded automatically */
	rte_timer_reset(&timer1,
			pktgen.hz,
			PERIODICAL,
			lcore_id,
			pktgen_process_stats,
			NULL);
}
