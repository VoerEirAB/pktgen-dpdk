/*-
 * Copyright (c) <2010-2017>, Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
/* Created 2010 by Keith Wiles @ intel.com */

#ifndef _PKTGEN_PORT_CFG_H_
#define _PKTGEN_PORT_CFG_H_

#include <stdio.h>
#include <string.h>
#include <rte_version.h>
#include <rte_atomic.h>
#include <rte_spinlock.h>
#include <rte_pci.h>

#undef BPF_MAJOR_VERSION
#include <pcap/pcap.h>

#include "pktgen-seq.h"
#include "pktgen-range.h"
#include "pktgen-stats.h"
#include "pktgen-pcap.h"
#include "pktgen-dump.h"
#include "pktgen-ether.h"
#include "pktgen-random.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PORT_DESC_SIZE  132
#define USER_PATTERN_SIZE   16

typedef struct port_sizes_s {
	uint64_t _64;		/**< Number of 64 byte packets */
	uint64_t _65_127;	/**< Number of 65-127 byte packets */
	uint64_t _128_255;	/**< Number of 128-255 byte packets */
	uint64_t _256_511;	/**< Number of 256-511 byte packets */
	uint64_t _512_1023;	/**< Number of 512-1023 byte packets */
	uint64_t _1024_1518;	/**< Number of 1024-1518 byte packets */
	uint64_t broadcast;	/**< Number of broadcast packets */
	uint64_t multicast;	/**< Number of multicast packets */
	uint64_t jumbo;		/**< Number of Jumbo frames */
	uint64_t runt;		/**< Number of Runt frames */
} port_sizes_t;

struct mbuf_table {
	uint16_t len;
	struct rte_mbuf *m_table[DEFAULT_PKT_BURST];
};

enum {						/* Per port flag bits */
	SEND_ARP_REQUEST        = 0x00000001,	/**< Send a ARP request */
	SEND_GRATUITOUS_ARP     = 0x00000002,	/**< Send a Gratuitous ARP */
	ICMP_ECHO_ENABLE_FLAG   = 0x00000004,	/**< Enable ICMP Echo support */
	SEND_PCAP_PKTS          = 0x00000008,	/**< Send a pcap file of packets */
	SEND_RANGE_PKTS         = 0x00000010,	/**< Send a range of packets */
	SEND_SEQ_PKTS           = 0x00000020,	/**< Send a sequence of packets */
	PROCESS_INPUT_PKTS      = 0x00000040,	/**< Process input packets */
	SEND_PING4_REQUEST      = 0x00000080,	/**< Send a IPv4 Ping request */
	SEND_PING6_REQUEST      = 0x00000100,	/**< Send a IPv6 Ping request */
	PROCESS_RX_TAP_PKTS     = 0x00000200,	/**< Handle RX TAP interface packets */
	PROCESS_TX_TAP_PKTS     = 0x00000400,	/**< Handle TX TAP interface packets */
	SEND_VLAN_ID            = 0x00000800,	/**< Send packets with VLAN ID */
	PROCESS_GARP_PKTS       = 0x00001000,	/**< Process GARP packets and update the dst MAC address */
	CAPTURE_PKTS            = 0x00002000,	/**< Capture received packets */
	SEND_MPLS_LABEL         = 0x00004000,	/**< Send MPLS label */
	SEND_Q_IN_Q_IDS         = 0x00008000,	/**< Send packets with Q-in-Q */
	SEND_GRE_IPv4_HEADER    = 0x00010000,	/**< Encapsulate IPv4 in GRE */
	SEND_RANDOM_PKTS        = 0x00020000,	/**< Send random bitfields in packets */
	SEND_GRE_ETHER_HEADER   = 0x00040000,	/**< Encapsulate Ethernet frame in GRE */
	SEND_LATENCY_PKTS       = 0x00080000,	/**< Send latency packets */
	BONDING_TX_PACKETS		= 0x00100000,	/**< Bonding driver send zero pkts */
	SEND_SHORT_PACKETS		= 0x00200000,	/**< Allow port to send short packets */
	SENDING_PACKETS         = 0x40000000,	/**< sending packets on this port */
	SEND_FOREVER            = 0x80000000,	/**< Send packets forever */
	SEND_ARP_PING_REQUESTS  =
		(SEND_ARP_REQUEST | SEND_GRATUITOUS_ARP | SEND_PING4_REQUEST |
		 SEND_PING6_REQUEST)
};

#define RTE_PMD_PARAM_UNSET -1

/*
 * Configurable values of RX and TX ring threshold registers.
 */
typedef struct ring_conf_s {
	int8_t rx_pthresh;
	int8_t rx_hthresh;
	int8_t rx_wthresh;

	int8_t tx_pthresh;
	int8_t tx_hthresh;
	int8_t tx_wthresh;

	/*
	 * Configurable value of RX free threshold.
	 */
	int16_t rx_free_thresh;

	/*
	 * Configurable value of RX drop enable.
	 */
	int8_t rx_drop_en;

	/*
	 * Configurable value of TX free threshold.
	 */
	int16_t tx_free_thresh;

	/*
	 * Configurable value of TX RS bit threshold.
	 */
	int16_t tx_rs_thresh;

	/*
	 * Configurable value of TX queue flags.
	 */
	int32_t txq_flags;

	/*
	 * Receive Side Scaling (RSS) configuration.
	 */
	uint64_t rss_hf;
} ring_conf_t;

typedef enum {
	ZERO_FILL_PATTERN = 1,
	ABC_FILL_PATTERN,
	USER_FILL_PATTERN,
	NO_FILL_PATTERN,
} fill_t;

typedef void (*tx_func_t)(struct port_info_s *info, uint16_t qid);

typedef struct port_info_s {
	uint16_t pid;		/**< Port ID value */
	uint16_t tx_burst;	/**< Number of TX burst packets */
	double tx_rate;		/**< Percentage rate for tx packets with fractions */
	rte_atomic32_t port_flags;	/**< Special send flags for ARP and other */

	rte_atomic64_t transmit_count;	/**< Packets to transmit loaded into current_tx_count */
	rte_atomic64_t current_tx_count;/**< Current number of packets to send */
	uint64_t tx_cycles;	/**< Number cycles between TX bursts */
	uint64_t tx_pps;	/**< Transmit packets per seconds */
	uint64_t delta;		/**< Delta value for latency testing */
	uint64_t tx_count;	/**< Total count of tx attempts */

	/* Packet buffer space for traffic generator, shared for all packets per port */
	uint16_t seqIdx;		/**< Current Packet sequence index 0 to NUM_SEQ_PKTS */
	uint16_t seqCnt;		/**< Current packet sequence max count */
	uint16_t prime_cnt;		/**< Set the number of packets to send in a prime command */
	uint16_t vlanid;		/**< Set the port VLAN ID value */
	uint8_t cos;			/**< Set the port 802.1p cos value */
	uint8_t tos;			/**< Set the port tos value */
	rte_spinlock_t port_lock;	/**< Used to sync up packet constructor between cores */
	pkt_seq_t *seq_pkt;		/**< Sequence of packets seq_pkt[NUM_SEQ_PKTS]=default packet */
	range_info_t range;		/**< Range Information */

	uint32_t mpls_entry;	/**< Set the port MPLS entry */
	uint32_t gre_key;	/**< GRE key if used */

	uint32_t nb_mbufs;	/**< Number of mbufs in the system */
	uint16_t pad1;
	uint64_t max_latency;	/**< TX Latency sequence */
	uint64_t avg_latency;	/**< Latency delta in clock ticks */
	uint64_t min_latency;	/**< RX Latency sequence */
	uint32_t magic_errors;
	uint32_t latency_nb_pkts;
	uint64_t jitter_threshold;
	uint64_t jitter_threshold_clks;
	uint64_t jitter_count;
	uint64_t prev_latency;

	pkt_stats_t stats;	/**< Statistics for a number of stats */
	port_sizes_t sizes;	/**< Stats for the different packets sizes */

	eth_stats_t init_stats;	/**< Initial packet statistics */
	eth_stats_t prev_stats;	/**< current port statistics */
	eth_stats_t rate_stats;	/**< current packet rate statistics */
	uint64_t max_ipackets;	/**< Max seen input packet rate */
	uint64_t max_opackets;	/**< Max seen output packet rate */
	uint64_t max_missed;	/**< Max missed packets seen */

	struct rte_eth_link link;	/**< Link Information like speed and duplex */

	struct q_info {
		rte_atomic32_t flags;		/**< Special send flags for ARP and other */
		struct mbuf_table tx_mbufs;	/**< mbuf holder for transmit packets */
		struct rte_mempool *rx_mp;	/**< Pool pointer for port RX mbufs */
		struct rte_mempool *tx_mp;	/**< Pool pointer for default TX mbufs */
		struct rte_mempool *range_mp;	/**< Pool pointer for port Range TX mbufs */
		struct rte_mempool *seq_mp;	/**< Pool pointer for port Sequence TX mbufs */
		struct rte_mempool *pcap_mp;	/**< Pool pointer for port PCAP TX mbufs */
		struct rte_mempool *special_mp;	/**< Pool pointer for special TX mbufs */
		uint64_t tx_cnt, rx_cnt;
	} q[NUM_Q];

	int32_t rx_tapfd;		/**< Rx Tap file descriptor */
	int32_t tx_tapfd;		/**< Tx Tap file descriptor */
	pcap_info_t           *pcap;	/**< PCAP information header */
	uint64_t pcap_cycles;		/**< number of cycles for pcap sending */

	int32_t pcap_result;	/**< PCAP result of filter compile */
	struct bpf_program pcap_program;/**< PCAP filter program structure */

	/* Packet dump related */
	struct packet {
		void *data;	/**< Packet data */
		uint32_t len;	/**< Length of data */
	} dump_list[MAX_DUMP_PACKETS];
	uint8_t dump_head;	/**< Index of last packet written to screen */
	uint8_t dump_tail;	/**< Index of last valid packet in dump_list */
	uint8_t dump_count;	/**< Number of packets the user requested */

	struct rnd_bits_s     *rnd_bitfields;	/**< Random bitfield settings */

	struct rte_eth_conf port_conf;		/**< port configuration information */
	struct rte_eth_dev_info dev_info;	/**< PCI info + driver name */
	struct rte_eth_rxconf rx_conf;		/**< RX configuration */
	struct rte_eth_txconf tx_conf;		/**< TX configuration */
	ring_conf_t ring_conf;			/**< Misc ring configuration information */
	char user_pattern[USER_PATTERN_SIZE];	/**< User set pattern values */
	fill_t fill_pattern_type;		/**< Type of pattern to fill with */
} port_info_t;

void pktgen_config_ports(void);

/**
 * Atomically subtract a 64-bit value from the tx counter.
 *
 * @param v
 *   A pointer to the atomic tx counter.
 * @param burst
 *   The value to be subtracted from the counter for tx burst size.
 * @return
 *   The number of packets to burst out
 */
static inline uint64_t
pkt_atomic64_tx_count(rte_atomic64_t *v, int64_t burst)
{
	int success;
	int64_t tmp1, tmp2;

	do {
		tmp1 = v->cnt;
		if (tmp1 == 0)
			return 0;
		tmp2 = likely(tmp1 > burst) ? burst : tmp1;
		success = rte_atomic64_cmpset((volatile uint64_t *)&v->cnt,
					      tmp1,
					      tmp1 - tmp2);
	} while (success == 0);

	return tmp2;
}

static inline void
pktgen_dump_rx_conf(FILE *f, struct rte_eth_rxconf *rx){
	fprintf(f, "** RX Conf **\n");
	fprintf(
		f,
		"   pthresh        :%4d, hthresh          :%4d, wthresh        :%6d\n",
		rx->rx_thresh.pthresh,
		rx->rx_thresh.hthresh,
		rx->rx_thresh.wthresh);
	fprintf(
		f,
		"   Free Thresh    :%4d, Drop Enable      :%4d, Deferred Start :%6d\n",
		rx->rx_free_thresh,
		rx->rx_drop_en,
		rx->rx_deferred_start);
}

static inline void
pktgen_dump_tx_conf(FILE *f, struct rte_eth_txconf *tx){
	fprintf(f, "** TX Conf **\n");
	fprintf(
		f,
		"   pthresh        :%4d, hthresh          :%4d, wthresh        :%6d\n",
		tx->tx_thresh.pthresh,
		tx->tx_thresh.hthresh,
		tx->tx_thresh.wthresh);
	fprintf(
		f,
		"   Free Thresh    :%4d, RS Thresh        :%4d, Deferred Start :%6d, TXQ Flags:%08x\n",
		tx->tx_free_thresh,
		tx->tx_rs_thresh,
		tx->tx_deferred_start,
		tx->txq_flags);
}

static inline void
pktgen_dump_dev_info(FILE *f, const char *msg, struct rte_eth_dev_info *di, uint32_t pid) {
	fprintf(f, "\n** %s (%s, if_index:%d) **\n",
		(msg) ? msg : "Device Info", rte_eth_devices[pid].data->name, di->if_index);
#if RTE_VERSION < RTE_VERSION_NUM(17, 5, 0, 0)
	fprintf(
		f,
		"   max_vfs        :%4d, min_rx_bufsize    :%4d, max_rx_pktlen :%6d\n",
		di->pci_dev ? di->pci_dev->max_vfs : 0,
		di->min_rx_bufsize,
		di->max_rx_pktlen);
#endif
	fprintf(
		f,
		"   max_rx_queues  :%4d, max_tx_queues     :%4d\n",
		di->max_rx_queues,
		di->max_tx_queues);
	fprintf(
		f,
		"   max_mac_addrs  :%4d, max_hash_mac_addrs:%4d, max_vmdq_pools:%6d\n",
		di->max_mac_addrs,
		di->max_hash_mac_addrs,
		di->max_vmdq_pools);
	fprintf(
		f,
#if RTE_VERSION < RTE_VERSION_NUM(17, 11, 0, 0)
		"   rx_offload_capa:%4u, tx_offload_capa   :%4u, reta_size     :%6d, flow_type_rss_offloads:%016" PRIx64 "\n",
#else
		"   rx_offload_capa:%4lu, tx_offload_capa   :%4lu, reta_size     :%6d, flow_type_rss_offloads:%016" PRIx64 "\n",
#endif
		di->rx_offload_capa,
		di->tx_offload_capa,
		di->reta_size,
#if defined(RTE_VER_MAJOR) && (RTE_VER_MAJOR < 2)
		0L
#else
		di->flow_type_rss_offloads
#endif
		);
	fprintf(
		f,
		"   vmdq_queue_base:%4d, vmdq_queue_num    :%4d, vmdq_pool_base:%6d\n",
		di->vmdq_queue_base,
		di->vmdq_queue_num,
		di->vmdq_pool_base);
	pktgen_dump_rx_conf(f, &di->default_rxconf);
	pktgen_dump_tx_conf(f, &di->default_txconf);
	fprintf(f, "\n");
}

void pktgen_set_hw_strip_crc(uint8_t val);
int pktgen_get_hw_strip_crc(void);

#ifdef __cplusplus
}
#endif

#endif  /* _PKTGEN_PORT_CFG_H_ */
