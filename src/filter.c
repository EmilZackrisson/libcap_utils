/**
 * libcap_utils - DPMI capture utilities
 * Copyright (C) 2003-2013 (see AUTHORS)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "caputils/filter.h"
#include "caputils/packet.h"
#include "caputils_int.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>

#ifdef HAVE_PCAP
#include <pcap/pcap.h>
#endif

/** @todo should feature-detect this instead */
#if defined(__GNUC__) && !defined(__clang__)
#define FILTER __attribute__ ((pure, hot, visibility ("hidden")))
#else
#define FILTER __attribute__ ((pure, visibility ("hidden")))
#endif





static const char* inet_ntoa_r(const struct in_addr in, char* buf){
	const char* tmp = inet_ntoa(in);
	strcpy(buf, tmp);
	return buf;
}

void filter_print(const struct filter* filter, FILE* fp, int verbose){
	static char buf[100];

	fprintf(fp, "FILTER {%02d}\n", filter->filter_id);
	fprintf(fp, "\t%-14s: %s\n", stream_addr_type(&filter->dest) == STREAM_ADDR_CAPFILE ? "DESTFILE" : "DESTADDRESS", stream_addr_ntoa(&filter->dest));
	fprintf(fp, "\tCAPLEN        : %d\n", filter->caplen);
	fprintf(fp, "\tindex         : %d\n", filter->index);
	fprintf(fp, "\tmode          : %s (%d)\n", filter->mode == FILTER_AND ? "AND" : "OR", filter->mode);

	if ( verbose || filter->index & FILTER_MAMPID ){
		fprintf(fp, "\tMAMPid        : %s\n", filter->mampid);
	} else if ( verbose ){
		fprintf(fp, "\tMAMPid        : NULL\n");
	}

	if ( verbose || filter->index&512 ){
		fprintf(fp, "\tCI_ID         : %s\n", filter->iface);
	} else if ( verbose ) {
		fprintf(fp, "\tCI_ID         : NULL\n");
	}

	if ( filter->index&256 ){
		fprintf(fp, "\tVLAN_TCI      : %d MASK (%d)", filter->vlan_tci, filter->vlan_tci_mask);
	} else if ( verbose ) {
		fprintf(fp, "\tVLAN_TCI      : NULL\n");
	}

	if ( filter->index&128 ){
		fprintf(fp, "\tETH_TYPE      : %d (MASK: 0x%04X)\n", filter->eth_type, filter->eth_type_mask);
	} else if ( verbose ) {
		fprintf(fp, "\tETH_TYPE      : NULL\n");
	}

	if ( filter->index&64 ){
		fprintf(fp, "\tETH_SRC       : %s (MASK: %s)\n", hexdump_address_r(&filter->eth_src, &buf[0]), hexdump_address_r(&filter->eth_src_mask, &buf[19]));
	} else if ( verbose ) {
		fprintf(fp, "\tETH_SRC       : NULL\n");
	}

	if ( filter->index&32 ){
		fprintf(fp, "\tETH_DST       : %s (MASK: %s)\n", hexdump_address_r(&filter->eth_dst, &buf[0]), hexdump_address_r(&filter->eth_dst_mask, &buf[19]));
	} else if ( verbose ) {
		fprintf(fp, "\tETH_DST       : NULL\n");
	}

	if ( filter->index&16 ){
		fprintf(fp, "\tIP_PROTO      : %d\n", filter->ip_proto);
	} else if ( verbose ) {
		fprintf(fp, "\tIP_PROTO      : NULL\n");
	}

	if ( filter->index&8 ){
		fprintf(fp, "\tIP_SRC        : %s (MASK: %s)\n", inet_ntoa_r(filter->ip_src, &buf[0]), inet_ntoa_r(filter->ip_src_mask, &buf[50]));
	} else if ( verbose ) {
		fprintf(fp, "\tIP_SRC        : NULL\n");
	}

	if ( filter->index&4 ){
		fprintf(fp, "\tIP_DST        : %s (MASK: %s)\n", inet_ntoa_r(filter->ip_dst, &buf[0]), inet_ntoa_r(filter->ip_dst_mask, &buf[50]));
	} else if ( verbose ) {
		fprintf(fp, "\tIP_DST        : NULL\n");
	}

	if ( filter->index & FILTER_PORT ){
		fprintf(fp, "\tPORT (s or d) : %d (MASK: 0x%04X)\n", filter->port, filter->port_mask);
	} else if ( verbose ) {
		fprintf(fp, "\tPORT (s or d) : NULL\n");
	}

	if ( filter->index&2 ){
		fprintf(fp, "\tPORT_SRC      : %d (MASK: 0x%04X)\n", filter->src_port, filter->src_port_mask);
	} else if ( verbose ) {
		fprintf(fp, "\tPORT_SRC      : NULL\n");
	}

	if ( filter->index&1  ){
		fprintf(fp, "\tPORT_DST      : %d (MASK: 0x%04X)\n", filter->dst_port, filter->dst_port_mask);
	} else if ( verbose ) {
		fprintf(fp, "\tPORT_DST      : NULL\n");
	}

	if ( filter->bpf_expr ){
		fprintf(fp, "\tBPF           : \"%s\"\n", filter->bpf_expr);
	} else if ( verbose ){
		fprintf(fp, "\tBPF           :\n");
	}
}

void filter_pack(struct filter* src, struct filter_packed* dst){
	dst->filter_id	= htonl(src->filter_id);
	dst->index		= htonl(src->index);
	dst->vlan_tci		= htons(src->vlan_tci);
	dst->eth_type		= htons(src->eth_type);
	dst->ip_proto		= src->ip_proto;
	dst->src_port		= htons(src->src_port);
	dst->dst_port		= htons(src->dst_port);
	dst->port       = htons(src->port);
	dst->vlan_tci_mask	= htons(src->vlan_tci_mask);
	dst->eth_type_mask	= htons(src->eth_type_mask);
	dst->src_port_mask	= htons(src->src_port_mask);
	dst->dst_port_mask	= htons(src->dst_port_mask);
	dst->port_mask      = htons(src->port_mask);
	dst->consumer	      = htonl(src->consumer);
	dst->caplen         = htonl(src->caplen);
	dst->mode           = src->mode;

	/* ip source and dest */
	dst->ip_src = src->ip_src;
	dst->ip_dst = src->ip_dst;
	dst->ip_src_mask = src->ip_src_mask;
	dst->ip_dst_mask = src->ip_dst_mask;
	memcpy(dst->_ip_src, inet_ntoa(src->ip_src), 16);
	memcpy(dst->_ip_dst, inet_ntoa(src->ip_dst), 16);
	memcpy(dst->_ip_src_mask, inet_ntoa(src->ip_src_mask), 16);
	memcpy(dst->_ip_dst_mask, inet_ntoa(src->ip_dst_mask), 16);

	memcpy(dst->iface, src->iface, 8);
	memcpy(&dst->eth_src, &src->eth_src, sizeof(struct ether_addr));
	memcpy(&dst->eth_dst, &src->eth_dst, sizeof(struct ether_addr));
	memcpy(&dst->eth_src_mask, &src->eth_src_mask, sizeof(struct ether_addr));
	memcpy(&dst->eth_dst_mask, &src->eth_dst_mask, sizeof(struct ether_addr));

	/* address (safe to copy, already in network order) */
	memcpy(&dst->dest, &src->dest, sizeof(stream_addr_t));

	/* filter version */
	dst->version = htonl(0x02);
}

void filter_unpack(struct filter_packed* src, struct filter* dst){
	dst->filter_id	= ntohl(src->filter_id);
	dst->index		= ntohl(src->index);
	dst->vlan_tci		= ntohs(src->vlan_tci);
	dst->eth_type		= ntohs(src->eth_type);
	dst->ip_proto		= src->ip_proto;
	dst->src_port		= ntohs(src->src_port);
	dst->dst_port		= ntohs(src->dst_port);
	dst->vlan_tci_mask	= ntohs(src->vlan_tci_mask);
	dst->eth_type_mask	= ntohs(src->eth_type_mask);
	dst->src_port_mask	= ntohs(src->src_port_mask);
	dst->dst_port_mask	= ntohs(src->dst_port_mask);
	dst->consumer		= ntohl(src->consumer);
	dst->caplen		= ntohl(src->caplen);

	const int version = ntohl(src->version);

	if ( version == 0 ){
		/* legacy filters are converted from ascii */
		inet_aton((const char*)src->_ip_src, &dst->ip_src);
		inet_aton((const char*)src->_ip_dst, &dst->ip_dst);
		inet_aton((const char*)src->_ip_src_mask, &dst->ip_src_mask);
		inet_aton((const char*)src->_ip_dst_mask, &dst->ip_dst_mask);
	} else {
		dst->ip_src = src->ip_src;
		dst->ip_dst = src->ip_dst;
		dst->ip_src_mask = src->ip_src_mask;
		dst->ip_dst_mask = src->ip_dst_mask;
	}

	/* Check if mode was supplied */
	if ( version >= 2 ){
		dst->mode = src->mode;
	} else {
		dst->mode = FILTER_AND;
	}

	memcpy(dst->iface, src->iface, 8);
	memcpy(&dst->eth_src, &src->eth_src, sizeof(struct ether_addr));
	memcpy(&dst->eth_dst, &src->eth_dst, sizeof(struct ether_addr));
	memcpy(&dst->eth_src_mask, &src->eth_src_mask, sizeof(struct ether_addr));
	memcpy(&dst->eth_dst_mask, &src->eth_dst_mask, sizeof(struct ether_addr));

	/* address (safe to copy, supposed to be in network order) */
	memcpy(&dst->dest, &src->dest, sizeof(stream_addr_t));

	/* filter version */
	dst->version = htonl(0x02);

	/* fill defaults for local filters */
	dst->frame_num = NULL;
}


