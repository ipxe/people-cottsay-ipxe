/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdint.h>
#include <string.h>
#include <byteswap.h>
#include <errno.h>
#include <gpxe/if_ether.h>
#include <gpxe/if_arp.h>
#include <gpxe/pkbuff.h>
#include <gpxe/netdevice.h>
#include <gpxe/arp.h>

/** @file
 *
 * Address Resolution Protocol
 *
 * This file implements the address resolution protocol as defined in
 * RFC826.  The implementation is media-independent and
 * protocol-independent; it is not limited to Ethernet or to IPv4.
 *
 */

/** An ARP cache entry */
struct arp_entry {
	/** Network-layer protocol */
	struct net_protocol *net_protocol;
	/** Link-layer protocol */
	struct ll_protocol *ll_protocol;
	/** Network-layer address */
	uint8_t net_addr[MAX_NET_ADDR_LEN];
	/** Link-layer address */
	uint8_t ll_addr[MAX_LL_ADDR_LEN];
};

/** Number of entries in the ARP cache
 *
 * This is a global cache, covering all network interfaces,
 * network-layer protocols and link-layer protocols.
 */
#define NUM_ARP_ENTRIES 4

/** The ARP cache */
static struct arp_entry arp_table[NUM_ARP_ENTRIES];
#define arp_table_end &arp_table[NUM_ARP_ENTRIES]

static unsigned int next_new_arp_entry = 0;

struct net_protocol arp_protocol;

/**
 * Find entry in the ARP cache
 *
 * @v ll_protocol	Link-layer protocol
 * @v net_protocol	Network-layer protocol
 * @v net_addr		Network-layer address
 * @ret arp		ARP cache entry, or NULL if not found
 *
 */
static struct arp_entry *
arp_find_entry ( struct ll_protocol *ll_protocol,
		 struct net_protocol *net_protocol,
		 const void *net_addr ) {
	struct arp_entry *arp;

	for ( arp = arp_table ; arp < arp_table_end ; arp++ ) {
		if ( ( arp->ll_protocol == ll_protocol ) &&
		     ( arp->net_protocol == net_protocol ) &&
		     ( memcmp ( arp->net_addr, net_addr,
				net_protocol->net_addr_len ) == 0 ) )
			return arp;
	}
	return NULL;
}

/**
 * Look up media-specific link-layer address in the ARP cache
 *
 * @v nethdr		Generic network-layer header
 * @ret llhdr		Generic link-layer header
 * @ret rc		Return status code
 *
 * This function will use the ARP cache to look up the link-layer
 * address for the link-layer protocol specified in @c llhdr and the
 * network-layer protocol and address as specified in @c nethdr.  If
 * found, the destination link-layer address will be filled in in @c
 * llhdr.
 *
 * If no address is found in the ARP cache, an ARP request will be
 * transmitted and -ENOENT will be returned.
 */
int arp_resolve ( const struct net_header *nethdr, struct ll_header *llhdr ) {
	struct net_protocol *net_protocol = nethdr->net_protocol;
	struct ll_protocol *ll_protocol = llhdr->ll_protocol;
	const struct arp_entry *arp;
	struct pk_buff *pkb;
	struct arphdr *arphdr;
	int rc;

	/* Look for existing entry in ARP table */
	arp = arp_find_entry ( ll_protocol, net_protocol,
			       nethdr->dest_net_addr );
	if ( arp ) {
		memcpy ( llhdr->dest_ll_addr, arp->ll_addr,
			 sizeof ( llhdr->dest_ll_addr ) );
		return 0;
	}

	/* Allocate ARP packet */
	pkb = alloc_pkb ( sizeof ( *arphdr ) +
			  2 * ( MAX_LL_ADDR_LEN + MAX_NET_ADDR_LEN ) );
	if ( ! pkb )
		return -ENOMEM;
	pkb->net_protocol = &arp_protocol;

	/* Build up ARP request */
	arphdr = pkb_put ( pkb, sizeof ( *arphdr ) );
	arphdr->ar_hrd = ll_protocol->ll_proto;
	arphdr->ar_hln = ll_protocol->ll_addr_len;
	arphdr->ar_pro = net_protocol->net_proto;
	arphdr->ar_pln = net_protocol->net_addr_len;
	arphdr->ar_op = htons ( ARPOP_REQUEST );
	memcpy ( pkb_put ( pkb, ll_protocol->ll_addr_len ),
		 llhdr->source_ll_addr, ll_protocol->ll_addr_len );
	memcpy ( pkb_put ( pkb, net_protocol->net_addr_len ),
		 nethdr->source_net_addr, net_protocol->net_addr_len );
	memset ( pkb_put ( pkb, ll_protocol->ll_addr_len ),
		 0, ll_protocol->ll_addr_len );
	memcpy ( pkb_put ( pkb, net_protocol->net_addr_len ),
		 nethdr->dest_net_addr, net_protocol->net_addr_len );

	/* Transmit ARP request */
	if ( ( rc = net_transmit ( pkb ) ) != 0 ) {
		free_pkb ( pkb );
		return rc;
	}

	return -ENOENT;
}

/**
 * Process incoming ARP packets
 *
 * @v pkb		Packet buffer
 * @ret rc		Return status code
 *
 * This handles ARP requests and responses as detailed in RFC826.  The
 * method detailed within the RFC is pretty optimised, handling
 * requests and responses with basically a single code path and
 * avoiding the need for extraneous ARP requests; read the RFC for
 * details.
 */
static int arp_rx ( struct pk_buff *pkb ) {
	struct arphdr *arphdr = pkb->data;
	struct ll_protocol *ll_protocol;
	struct net_protocol *net_protocol;
	struct arp_entry *arp;
	struct net_device *netdev;
	int merge = 0;

	/* Identify link-layer and network-layer protocols */
	ll_protocol = pkb->ll_protocol;
	net_protocol = net_find_protocol ( arphdr->ar_pro );
	if ( ! net_protocol )
		goto done;

	/* Sanity checks */
	if ( ( arphdr->ar_hrd != ll_protocol->ll_proto ) ||
	     ( arphdr->ar_hln != ll_protocol->ll_addr_len ) ||
	     ( arphdr->ar_pln != net_protocol->net_addr_len ) )
		goto done;

	/* See if we have an entry for this sender, and update it if so */
	arp = arp_find_entry ( ll_protocol, net_protocol,
			       arp_sender_pa ( arphdr ) );
	if ( arp ) {
		memcpy ( arp->ll_addr, arp_sender_ha ( arphdr ),
			 arphdr->ar_hln );
		merge = 1;
	}

	/* See if we own the target protocol address */
	netdev = net_find_address ( net_protocol, arp_target_pa ( arphdr ) );
	if ( ! netdev )
		goto done;
	
	/* Create new ARP table entry if necessary */
	if ( ! merge ) {
		arp = &arp_table[next_new_arp_entry++ % NUM_ARP_ENTRIES];
		arp->ll_protocol = ll_protocol;
		arp->net_protocol = net_protocol;
		memcpy ( arp->ll_addr, arp_sender_ha ( arphdr ),
			 arphdr->ar_hln );
		memcpy ( arp->net_addr, arp_sender_pa ( arphdr ),
			 arphdr->ar_pln);
	}

	/* If it's not a request, there's nothing more to do */
	if ( arphdr->ar_op != htons ( ARPOP_REQUEST ) )
		goto done;

	/* Change request to a reply, and send it */
	arphdr->ar_op = htons ( ARPOP_REPLY );
	memswap ( arp_sender_ha ( arphdr ), arp_target_ha ( arphdr ),
		 arphdr->ar_hln + arphdr->ar_pln );
	memcpy ( arp_target_ha ( arphdr ), netdev->ll_addr, arphdr->ar_hln );
	if ( net_transmit ( pkb ) == 0 )
		pkb = NULL;

 done:
	free_pkb ( pkb );
	return 0;
}

/**
 * Perform ARP network-layer routing
 *
 * @v pkb	Packet buffer
 * @ret source	Network-layer source address
 * @ret dest	Network-layer destination address
 * @ret rc	Return status code
 */
static int arp_route ( const struct pk_buff *pkb,
		       struct net_header *nethdr ) {
	struct arphdr *arphdr = pkb->data;

	memcpy ( nethdr->source_net_addr, arp_sender_ha ( arphdr ),
		 arphdr->ar_hln );
	memcpy ( nethdr->dest_net_addr, arp_target_ha ( arphdr ),
		 arphdr->ar_hln );
	nethdr->dest_flags = NETADDR_FL_RAW;
	if ( arphdr->ar_op == htons ( ARPOP_REQUEST ) )
		nethdr->dest_flags |= NETADDR_FL_BROADCAST;
	
	return 0;
}

/** ARP protocol */
struct net_protocol arp_protocol = {
	.net_proto = ETH_P_ARP,
	.rx = arp_rx,
	.route = arp_route,
};

NET_PROTOCOL ( arp_protocol );
