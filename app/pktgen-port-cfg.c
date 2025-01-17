/*-
 * Copyright (c) <2010-2017>, Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* Created 2010 by Keith Wiles @ intel.com */

#include <cli_scrn.h>
#include "pktgen-port-cfg.h"

#include "pktgen.h"
#include "pktgen-cmds.h"
#include "pktgen-log.h"

#ifdef RTE_LIBRTE_BONDING_PMD
#include <rte_eth_bond_8023ad.h>
#endif

enum {
	RX_PTHRESH              = 8,	/**< Default values of RX prefetch threshold reg. */
	RX_HTHRESH              = 8,	/**< Default values of RX host threshold reg. */
	RX_WTHRESH              = 4,	/**< Default values of RX write-back threshold reg. */

	TX_PTHRESH              = 36,	/**< Default values of TX prefetch threshold reg. */
	TX_HTHRESH              = 0,	/**< Default values of TX host threshold reg. */
	TX_WTHRESH              = 0,	/**< Default values of TX write-back threshold reg. */
	TX_WTHRESH_1GB          = 16,	/**< Default value for 1GB ports */
};

static uint8_t hw_strip_crc = 0;
const struct rte_eth_conf default_port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
		.header_split   = 0,	/**< Header Split disabled. */
		.hw_ip_checksum = 0,	/**< IP checksum offload disabled. */
		.hw_vlan_filter = 0,	/**< VLAN filtering enabled. */
		.hw_vlan_strip  = 0,	/**< VLAN strip enabled. */
		.hw_vlan_extend = 0,	/**< Extended VLAN disabled. */
		.jumbo_frame    = 0,	/**< Jumbo Frame Support disabled. */
		.hw_strip_crc   = 0,	/**< CRC stripping by hardware disabled. */
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_key_len = 0,
			.rss_hf = ETH_RSS_IP,
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

const ring_conf_t default_ring_conf = {
	.rx_pthresh = RTE_PMD_PARAM_UNSET,
	.rx_hthresh = RTE_PMD_PARAM_UNSET,
	.rx_wthresh = RTE_PMD_PARAM_UNSET,

	.tx_pthresh = RTE_PMD_PARAM_UNSET,
	.tx_hthresh = RTE_PMD_PARAM_UNSET,
	.tx_wthresh = RTE_PMD_PARAM_UNSET,

	.rx_free_thresh = 32,
	.rx_drop_en = RTE_PMD_PARAM_UNSET,
	.tx_free_thresh = RTE_PMD_PARAM_UNSET,
	.tx_rs_thresh = RTE_PMD_PARAM_UNSET,
	.txq_flags = RTE_PMD_PARAM_UNSET,
	.rss_hf = ETH_RSS_IP
};

void
pktgen_set_hw_strip_crc(uint8_t val)
{
	hw_strip_crc = val;
}

int
pktgen_get_hw_strip_crc(void)
{
	return (hw_strip_crc)? ETHER_CRC_LEN : 0;
}

/**************************************************************************//**
 *
 * pktgen_mbuf_pool_create - Create mbuf packet pool.
 *
 * DESCRIPTION
 * Callback routine for creating mbuf packets from a mempool.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
static struct rte_mempool *
pktgen_mbuf_pool_create(const char *type, uint8_t pid, uint8_t queue_id,
			uint32_t nb_mbufs, int socket_id, int cache_size){
	struct rte_mempool *mp;
	char name[RTE_MEMZONE_NAMESIZE];

	snprintf(name, sizeof(name), "%-12s%u:%u", type, pid, queue_id);
	pktgen_log_info(
		"    Create: %-*s - Memory used (MBUFs %5u x (size %u + Hdr %lu)) + %lu = %6lu KB headroom %d %d",
		16,
		name,
		nb_mbufs,
		MBUF_SIZE,
		sizeof(struct rte_mbuf),
		sizeof(struct rte_mempool),
		(((nb_mbufs * (MBUF_SIZE + sizeof(struct rte_mbuf)) +
		   sizeof(struct rte_mempool))) + 1023) / 1024,
		RTE_PKTMBUF_HEADROOM,
		RTE_MBUF_DEFAULT_BUF_SIZE);
	pktgen.mem_used += ((nb_mbufs *
		(MBUF_SIZE + sizeof(struct rte_mbuf)) +
		sizeof(struct rte_mempool)));
	pktgen.total_mem_used += ((nb_mbufs *
		(MBUF_SIZE + sizeof(struct rte_mbuf)) +
		sizeof(struct rte_mempool)));

	/* create the mbuf pool */
	mp = rte_pktmbuf_pool_create(name, nb_mbufs, cache_size,
		DEFAULT_PRIV_SIZE, MBUF_SIZE, socket_id);
	if (mp == NULL)
		pktgen_log_panic(
			"Cannot create mbuf pool (%s) port %d, queue %d, nb_mbufs %d, socket_id %d: %s",
			name,
			pid,
			queue_id,
			nb_mbufs,
			socket_id,
			rte_strerror(errno));

	return mp;
}

static void
pktgen_port_conf_setup(uint32_t pid, rxtx_t *rt, const struct rte_eth_conf *dpc)
{
	port_info_t *info = &pktgen.info[pid];
	struct rte_eth_conf *conf = &info->port_conf;
	struct rte_eth_dev_info *dev = &info->dev_info;
	ring_conf_t *rc = &info->ring_conf;
	struct rte_eth_rxconf *rx;
	struct rte_eth_txconf *tx;

	rte_memcpy(conf, dpc, sizeof(struct rte_eth_conf));
	rte_memcpy(&info->ring_conf, &default_ring_conf, sizeof(ring_conf_t));

	rte_eth_dev_info_get(pid, dev);

	pktgen_dump_dev_info(stdout, "Default Info", dev, pid);

	if (rt->rx > 1) {
		conf->rx_adv_conf.rss_conf.rss_key  = NULL;
		conf->rx_adv_conf.rss_conf.rss_hf   = ETH_RSS_IP;
	} else {
		conf->rx_adv_conf.rss_conf.rss_key  = NULL;
		conf->rx_adv_conf.rss_conf.rss_hf   = 0;
	}
	conf->rxmode.hw_strip_crc = hw_strip_crc;

	if (conf->rx_adv_conf.rss_conf.rss_hf != 0)
		conf->rxmode.mq_mode = (dev->max_vfs) ?
			ETH_MQ_RX_VMDQ_RSS : ETH_MQ_RX_RSS;
	else
		conf->rxmode.mq_mode = ETH_MQ_RX_NONE;

	conf->txmode.mq_mode = ETH_MQ_TX_NONE;

	rx = &info->rx_conf;
	tx = &info->tx_conf;

	rte_memcpy(rx, &info->dev_info.default_rxconf, sizeof(struct rte_eth_rxconf));
	rte_memcpy(tx, &info->dev_info.default_txconf, sizeof(struct rte_eth_txconf));

	/* Check if any RX/TX parameters have been passed */
	if (rc->rx_pthresh != RTE_PMD_PARAM_UNSET)
		rx->rx_thresh.pthresh = rc->rx_pthresh;

	if (rc->rx_hthresh != RTE_PMD_PARAM_UNSET)
		rx->rx_thresh.hthresh = rc->rx_hthresh;

	if (rc->rx_wthresh != RTE_PMD_PARAM_UNSET)
		rx->rx_thresh.wthresh = rc->rx_wthresh;

	if (rc->rx_free_thresh != RTE_PMD_PARAM_UNSET)
		rx->rx_free_thresh = rc->rx_free_thresh;

	if (rc->rx_drop_en != RTE_PMD_PARAM_UNSET)
		rx->rx_drop_en = rc->rx_drop_en;

	if (rc->tx_pthresh != RTE_PMD_PARAM_UNSET)
		info->tx_conf.tx_thresh.pthresh = rc->tx_pthresh;

	if (rc->tx_hthresh != RTE_PMD_PARAM_UNSET)
		tx->tx_thresh.hthresh = rc->tx_hthresh;

	if (rc->tx_wthresh != RTE_PMD_PARAM_UNSET)
		tx->tx_thresh.wthresh = rc->tx_wthresh;

	if (rc->tx_rs_thresh != RTE_PMD_PARAM_UNSET)
		tx->tx_rs_thresh = rc->tx_rs_thresh;

	if (rc->tx_free_thresh != RTE_PMD_PARAM_UNSET)
		tx->tx_free_thresh = rc->tx_free_thresh;

	if (rc->txq_flags != RTE_PMD_PARAM_UNSET)
		info->tx_conf.txq_flags = rc->txq_flags;
}

/**************************************************************************//**
 *
 * pktgen_config_ports - Configure the ports for RX and TX
 *
 * DESCRIPTION
 * Handle setting up the ports in DPDK.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
pktgen_config_ports(void)
{
	uint32_t lid, pid, i, s, q, sid;
	rxtx_t rt;
	pkt_seq_t   *pkt;
	port_info_t     *info;
	char buff[RTE_MEMZONE_NAMESIZE];
	int32_t ret, cache_size;
	char output_buff[256] = { 0 };
	uint64_t ticks;

	/* Find out the total number of ports in the system. */
	/* We have already blacklisted the ones we needed to in main routine. */
	pktgen.nb_ports = rte_eth_dev_count();
	if (pktgen.nb_ports > RTE_MAX_ETHPORTS)
		pktgen.nb_ports = RTE_MAX_ETHPORTS;

	if (pktgen.nb_ports == 0)
		pktgen_log_panic("*** Did not find any ports to use ***");

	pktgen.starting_port = 0;

	/* Setup the number of ports to display at a time */
	if (pktgen.nb_ports > pktgen.nb_ports_per_page)
		pktgen.ending_port = pktgen.starting_port +
			pktgen.nb_ports_per_page;
	else
		pktgen.ending_port = pktgen.starting_port + pktgen.nb_ports;

	pg_port_matrix_dump(pktgen.l2p);

	pktgen_log_info(
		"Configuring %d ports, MBUF Size %d, MBUF Cache Size %d",
		pktgen.nb_ports,
		MBUF_SIZE,
		MBUF_CACHE_SIZE);

	/* For each lcore setup each port that is handled by that lcore. */
	for (lid = 0; lid < RTE_MAX_LCORE; lid++) {
		if (get_map(pktgen.l2p, RTE_MAX_ETHPORTS, lid) == 0)
			continue;

		/* For each port attached or handled by the lcore */
		for (pid = 0; pid < pktgen.nb_ports; pid++) {
			/* If non-zero then this port is handled by this lcore. */
			if (get_map(pktgen.l2p, pid, lid) == 0)
				continue;
			pg_set_port_private(pktgen.l2p, pid, &pktgen.info[pid]);
			pktgen.info[pid].pid = pid;
		}
	}
	pg_dump_l2p(pktgen.l2p);

	pktgen.total_mem_used = 0;

	for (pid = 0; pid < pktgen.nb_ports; pid++) {
		/* Skip if we do not have any lcores attached to a port. */
		if ( (rt.rxtx = get_map(pktgen.l2p, pid, RTE_MAX_LCORE)) == 0)
			continue;

		pktgen.port_cnt++;
		snprintf(output_buff, sizeof(output_buff),
			 "Initialize Port %d -- TxQ %d, RxQ %d",
			 pid, rt.tx, rt.rx);

		info = get_port_private(pktgen.l2p, pid);

		info->fill_pattern_type  = ABC_FILL_PATTERN;
		strncpy(info->user_pattern, "0123456789abcdef", USER_PATTERN_SIZE);

		rte_spinlock_init(&info->port_lock);

		/* Create the pkt header structures for transmitting sequence of packets. */
		snprintf(buff, sizeof(buff), "seq_hdr_%d", pid);
		info->seq_pkt = rte_zmalloc_socket(buff,
						   (sizeof(pkt_seq_t) * NUM_TOTAL_PKTS),
						   RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (info->seq_pkt == NULL)
			pktgen_log_panic("Unable to allocate %d pkt_seq_t headers",
					 NUM_TOTAL_PKTS);

		for (i = 0; i < NUM_TOTAL_PKTS; i++)
			info->seq_pkt[i].seq_enabled = 1;

		info->seqIdx    = 0;
		info->seqCnt    = 0;

		info->jitter_threshold = DEFAULT_JITTER_THRESHOLD;
		ticks = rte_get_timer_hz() / 1000000;
		info->jitter_threshold_clks = info->jitter_threshold * ticks;
		info->nb_mbufs  = MAX_MBUFS_PER_PORT;
		cache_size = (info->nb_mbufs > RTE_MEMPOOL_CACHE_MAX_SIZE) ?
			RTE_MEMPOOL_CACHE_MAX_SIZE : info->nb_mbufs;

		pktgen_port_conf_setup(pid, &rt, &default_port_conf);

		if ( (ret = rte_eth_dev_configure(pid, rt.rx, rt.tx, &info->port_conf)) < 0)
			pktgen_log_panic(
				"Cannot configure device: port=%d, Num queues %d,%d (%d)%s",
				pid, rt.rx, rt.tx, errno, rte_strerror(-ret));

		pkt = &info->seq_pkt[SINGLE_PKT];

		pktgen.mem_used = 0;

		for (q = 0; q < rt.rx; q++) {
			/* grab the socket id value based on the lcore being used. */
			sid = rte_lcore_to_socket_id(get_port_lid(pktgen.l2p, pid, q));

			/* Create and initialize the default Receive buffers. */
			info->q[q].rx_mp = pktgen_mbuf_pool_create("Default RX", pid, q,
								   info->nb_mbufs, sid, cache_size);
			if (info->q[q].rx_mp == NULL)
				pktgen_log_panic("Cannot init port %d for Default RX mbufs", pid);

			ret = rte_eth_rx_queue_setup(pid, q, pktgen.nb_rxd, sid,
						     &info->rx_conf, pktgen.info[pid].q[q].rx_mp);
			if (ret < 0)
				pktgen_log_panic("rte_eth_rx_queue_setup: err=%d, port=%d, %s",
						 ret, pid, rte_strerror(-ret));
			lid = get_port_lid(pktgen.l2p, pid, q);
			pktgen_log_info("      Set RX queue stats mapping pid %d, q %d, lcore %d\n", pid, q, lid);
			rte_eth_dev_set_rx_queue_stats_mapping(pid, q, lid);
		}
		pktgen_log_info("");

		for (q = 0; q < rt.tx; q++) {
			/* grab the socket id value based on the lcore being used. */
			sid = rte_lcore_to_socket_id(get_port_lid(pktgen.l2p, pid, q));

			/* Create and initialize the default Transmit buffers. */
			info->q[q].tx_mp = pktgen_mbuf_pool_create("Default TX", pid, q,
								   MAX_MBUFS_PER_PORT, sid, cache_size);
			if (info->q[q].tx_mp == NULL)
				pktgen_log_panic("Cannot init port %d for Default TX mbufs", pid);

			/* Create and initialize the range Transmit buffers. */
			info->q[q].range_mp = pktgen_mbuf_pool_create("Range TX", pid, q,
								      MAX_MBUFS_PER_PORT, sid, 0);
			if (info->q[q].range_mp == NULL)
				pktgen_log_panic("Cannot init port %d for Range TX mbufs", pid);

			/* Create and initialize the sequence Transmit buffers. */
			info->q[q].seq_mp = pktgen_mbuf_pool_create("Sequence TX", pid, q,
								    MAX_MBUFS_PER_PORT, sid, cache_size);
			if (info->q[q].seq_mp == NULL)
				pktgen_log_panic("Cannot init port %d for Sequence TX mbufs", pid);

			/* Used for sending special packets like ARP requests */
			info->q[q].special_mp = pktgen_mbuf_pool_create("Special TX", pid, q,
									MAX_SPECIAL_MBUFS, sid, 0);
			if (info->q[q].special_mp == NULL)
				pktgen_log_panic("Cannot init port %d for Special TX mbufs", pid);

			/* Setup the PCAP file for each port */
			if (pktgen.info[pid].pcap != NULL)
				if (pktgen_pcap_parse(pktgen.info[pid].pcap, info, q) == -1)
					pktgen_log_panic("Cannot load PCAP file for port %d", pid);
			/* Find out the link speed to program the WTHRESH value correctly. */
			pktgen_get_link_status(info, pid, 0);

			ret = rte_eth_tx_queue_setup(pid, q, pktgen.nb_txd, sid, &info->tx_conf);
			if (ret < 0)
				pktgen_log_panic("rte_eth_tx_queue_setup: err=%d, port=%d, %s",
						 ret, pid, rte_strerror(-ret));
			pktgen_log_info("");
		}
		pktgen_log_info("%*sPort memory used = %6lu KB", 71, " ",
				(pktgen.mem_used + 1023) / 1024);

		/* Grab the source MAC addresses */
		rte_eth_macaddr_get(pid, &pkt->eth_src_addr);
		pktgen_log_info("%s,  Src MAC %02x:%02x:%02x:%02x:%02x:%02x",
				output_buff,
				pkt->eth_src_addr.addr_bytes[0],
				pkt->eth_src_addr.addr_bytes[1],
				pkt->eth_src_addr.addr_bytes[2],
				pkt->eth_src_addr.addr_bytes[3],
				pkt->eth_src_addr.addr_bytes[4],
				pkt->eth_src_addr.addr_bytes[5]);

		/* Copy the first Src MAC address in SINGLE_PKT to the rest of the sequence packets. */
		for (i = 0; i < NUM_SEQ_PKTS; i++)
			ethAddrCopy(&info->seq_pkt[i].eth_src_addr, &pkt->eth_src_addr);
	}
	pktgen_log_info("%*sTotal memory used = %6lu KB", 70, " ",
			(pktgen.total_mem_used + 1023) / 1024);

	/* Start up the ports and display the port Link status */
	for (pid = 0; pid < pktgen.nb_ports; pid++) {
		if (get_map(pktgen.l2p, pid, RTE_MAX_LCORE) == 0)
			continue;

		/* Start device */
		if ( (ret = rte_eth_dev_start(pid)) < 0)
			pktgen_log_panic("rte_eth_dev_start: port=%d, %s",
					 pid, rte_strerror(-ret));
		rte_delay_us(250000);
	}

	rte_delay_us(1000000);

	/* Start up the ports and display the port Link status */
	for (pid = 0; pid < pktgen.nb_ports; pid++) {
		if (get_map(pktgen.l2p, pid, RTE_MAX_LCORE) == 0)
			continue;

		info = get_port_private(pktgen.l2p, pid);

		pktgen_get_link_status(info, pid, 1);

		if (info->link.link_status)
			snprintf(output_buff, sizeof(output_buff),
				 "Port %2d: Link Up - speed %u Mbps - %s",
				 pid, (uint32_t)info->link.link_speed,
				 (info->link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
				 ("full-duplex") : ("half-duplex"));
		else
			snprintf(output_buff, sizeof(output_buff), "Port %2d: Link Down", pid);

		/* If enabled, put device in promiscuous mode. */
		if (pktgen.flags & PROMISCUOUS_ON_FLAG) {
			strncatf(output_buff, " <Enable promiscuous mode>");
			rte_eth_promiscuous_enable(pid);
		}

		pktgen_log_info("%s", output_buff);
		pktgen.info[pid].seq_pkt[SINGLE_PKT].pktSize = MIN_PKT_SIZE;

		/* Setup the port and packet defaults. (must be after link speed is found) */
		for (s = 0; s < NUM_TOTAL_PKTS; s++)
			pktgen_port_defaults(pid, s);

		pktgen_range_setup(info);

		rte_eth_stats_get(pid, &info->init_stats);

		pktgen_rnd_bits_init(&pktgen.info[pid].rnd_bitfields);
	}

	/* Clear the log information by putting a blank line */
	pktgen_log_info("");

	/* Setup the packet capture per port if needed. */
	for (sid = 0; sid < coremap_cnt(pktgen.core_info, pktgen.core_cnt, 0); sid++)
		pktgen_packet_capture_init(&pktgen.capture[sid], sid);
}
