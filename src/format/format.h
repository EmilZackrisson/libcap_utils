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

#include <caputils/log.h>
#include <caputils/send.h>
#include <caputils/packet.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <regex.h>

#include  "caputils/export.h"

enum {
	PORT_DNS = 53,
	PORT_HTTP = 80,
	PORT_CP = 5000,
	PORT_CLP = 5001,
	PORT_TG  = 1500,
	PORT_MARKER = 4000,
	PORT_BACNET = 0xBAC0,
};

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
    uint16_t dns;
    uint16_t http;
    uint16_t cp;
    uint16_t clp;
    uint16_t tg;
    uint16_t marker;
    uint16_t bacnet;
} portmap_t;

typedef struct {
	bool show;				// If enabled, show header and body size
	bool showHeaders;		// If enabled, show headers
	bool showBody;			// If enabled, show body.
	
    bool   grep_enabled;       // If enabled, a pattern was supplied
    char   grep_pattern[256];  // original pattern (optional: for logging)
    bool   grep_icase;         // case-insensitive?
    regex_t grep_re;           // compiled regex

	bool	newline;		// Prevent 'newline' from printing. 
    bool match_seen;   // Set to true if any line matched the filter

} http_t;

struct name_table {
	int value;
	const char* name;
};

CAPUTILS_API extern 	portmap_t ports; 
CAPUTILS_API extern 	http_t httpFormatOptions; 
CAPUTILS_API int 		ports_set(const char *name, uint16_t value);
CAPUTILS_API uint16_t 	ports_get(const char *name);
CAPUTILS_API void 		supported_protocols(FILE *fp);

  
/**
 * From a name table find entry with value and return name.
 * If value isn't found it returns def.
 */
const char* name_lookup(const struct name_table* table, int value, const char* def);

/**
 * Like fputs but only prints printable characters. Nonprintable characters is
 * replaced with \x## where ## is hex ASCII.
 * @note It also skips newlines.
 * @param max max characters to print or -1 to read until null-terminator
 */
void fputs_printable(const char* str, int max, FILE* fp);

/**
 * Test if there is enough data left for parsing.
 * @param cp capture header
 * @param ptr current read position
 * @param bytes number of bytes required.
 * @return non-zero if there isn't enough data left
 */
int limited_caplen(const struct cap_header* cp, const void* ptr, size_t bytes) __attribute__((visibility("default")));

/* layer 3 */
void print_arp(FILE* dst, const struct cap_header* cp, const struct ether_arp* arp);
void print_mp(FILE* fp, const struct cap_header* cp, const struct sendhead* send);
void print_mp_diagnostic(FILE* fp, const struct cap_header* cp, const char* data);
void print_mpls(FILE* fp, const struct cap_header* cp, const char* data);

/* layer 4 */
void print_icmp(FILE* fp, const struct cap_header* cp, net_t net, const struct icmphdr* icmp, unsigned int flags);

/* application layer */
void print_http(FILE* fp, const struct cap_header* cp, const char* payload, size_t size, unsigned int flags);
  void print_clp(FILE* fp, const struct cap_header* cp, const char* payload, size_t size, unsigned int flags); // calc line protocol used in DV1619
  
#ifdef __cplusplus
}
#endif
