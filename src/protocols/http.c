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

#include "src/format/format.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <stdlib.h>
#include <regex.h>




//static const unsigned int MAX_LABEL_REFERENCES = 32;    /* how many label references (depth) is allowed */

//static int min(int a, int b){ return a<b?a:b; }

static void http_dump(FILE* fp, const struct header_chunk* header, const char* payload, const char* prefix, int flags){
  
  const struct cap_header* cp = header->cp;

  fprintf(fp," HTTP \n");
//  const char* cur = payload; /* Not used */
  const char* end = header->cp->payload + header->cp->caplen;
  const ptrdiff_t cpSize = end - payload;
  fprintf(fp,"HTTP size = %ld \n",cpSize);    

  if ( cp->caplen < cp->len ){
    fprintf(fp, "%s[Packet size limited during capture %d / %d ]", prefix,cp->caplen,cp->len);
    return;
  }
 
 
}

#include <string.h>
#include <stdlib.h>
#include <regex.h>

/* Print a single line slice as-is (binary-safe). */
static inline void print_line(FILE *fp, const char *p, size_t n, const http_t *cfg)
{
    if (cfg->newline) {
        /* Print everything EXCEPT CR and LF */
        for (size_t i = 0; i < n; i++) {
            char c = p[i];
            if (c != '\r' && c != '\n') {
                fputc(c, fp);
            } else {
                fputc(' ',fp);
            }
        }
    } else {
        /* Print exactly as received (binary-safe) */
        fwrite(p, 1, n, fp);
    }
}
/* Return 1 if the line matches the compiled regex (if grep is enabled); else 1. */
static int http_line_passes_grep(http_t *cfg, const char *line, size_t len)
{
    if (!cfg || !cfg->grep_enabled) return 1;

    if (len < 1024) {
        char tmp[1024];
        memcpy(tmp, line, len);
        tmp[len] = '\0';
        return regexec(&cfg->grep_re, tmp, 0, NULL, 0) == 0;   // <-- no cast
    } else {
        char *tmp = (char*)malloc(len + 1);
        if (!tmp) return 0;
        memcpy(tmp, line, len);
        tmp[len] = '\0';
        const int ok = (regexec(&cfg->grep_re, tmp, 0, NULL, 0) == 0);  // <-- no cast
        free(tmp);
        return ok;
    }
}

/* Walk a bounded region [buf, buf+len) line-by-line and print lines that pass grep. */
static void http_print_region_lines(FILE *fp,
                                    const char *buf, size_t len,
                                    http_t *cfg)
{
    const char *p   = buf;
    const char *end = buf + len;

    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *line_end = nl ? (nl + 1) : end;
        size_t ln = (size_t)(line_end - p);

        /* Trim trailing newline for matching only, not for printing */
        const char *match_begin = p;
        size_t match_len = ln;
        if (match_len >= 2 && p[match_len-2] == '\r' && p[match_len-1] == '\n')
            match_len -= 2;
        else if (match_len >= 1 && p[match_len-1] == '\n')
            match_len -= 1;

        if (http_line_passes_grep(cfg, match_begin, match_len)) {
            cfg->match_seen = true;   // <‑‑ record that at least one match occurred
            print_line(fp, p, ln, cfg);
        }

        p = line_end;
    }
}

void http_split_header_body(const char *payload,
                            size_t plen,
                            size_t *header_len,
                            size_t *body_len)
{
    size_t i = 0;

    /* We look for the sequence: "\r\n\r\n" */
    while (i + 3 < plen) {
        if (payload[i]   == '\r' &&
            payload[i+1] == '\n' &&
            payload[i+2] == '\r' &&
            payload[i+3] == '\n')
        {
            /* Header ends AFTER the CRLFCRLF (4 bytes) */
            *header_len = i + 4;
            *body_len   = (plen > *header_len) ? (plen - *header_len) : 0;
            return;
        }
        i++;
    }

    /* If we get here, no CRLFCRLF was found */
    *header_len = plen;
    *body_len   = 0;
}

static void http_format(FILE* fp,
                        const struct header_chunk* header,
                        const char* payload,
                        unsigned int flags)
{
    (void)flags; /* unused here; kept for signature compatibility */

    /* Safe length derivation from the capture header. */
    const struct cap_header* cp = header->cp;
    const size_t offset = (size_t)(payload - cp->payload);
    const size_t plen   = (cp->caplen > offset) ? (cp->caplen - offset) : 0;

    httpFormatOptions.match_seen = false;
    const char *label = httpFormatOptions.grep_enabled ? "MATCH" : "DUMP";

    /* Split header/body. */
    size_t header_len = 0, body_len = 0;
    http_split_header_body(payload, plen, &header_len, &body_len);

    if (!httpFormatOptions.show) {
        fputs("(disabled)\n", fp);
        return;
    }


    /* If neither headers nor body requested: just report lengths. */
    if (!httpFormatOptions.showHeaders && !httpFormatOptions.showBody) {
        fprintf(fp, " HTTP: ");
        fprintf(fp, "HTTP.header: %zu ", header_len);
        fprintf(fp, "HTTP.body:   %zu ", body_len);
        return;
    }

    

    if (httpFormatOptions.newline) {
      fprintf(fp, "HTTP %s=[ ", label);
    } else {
      fprintf(fp, "HTTP %s=[\n", label);
    }

    /* Headers */
    if (httpFormatOptions.showHeaders && header_len > 0) {
        /* Optional: section label */
        /* fputs("=== HTTP HEADERS ===\n", fp); */
        http_print_region_lines(fp, payload, header_len, &httpFormatOptions);
        /* Ensure a newline separation between sections if you want */
        if (httpFormatOptions.showBody && body_len > 0) {
          if (httpFormatOptions.newline) {
            fputc(' ', fp);
          } else {
            fputc('\n', fp);
          }
        }
    }

    /* Body */
    if (httpFormatOptions.showBody && body_len > 0) {
        /* Optional: section label */
        /* fputs("=== HTTP BODY ===\n", fp); */
        http_print_region_lines(fp, payload + header_len, body_len, &httpFormatOptions);
    }
   
  /* If grip_enabled AND no match_seen, print marker */
    if (httpFormatOptions.grep_enabled && !httpFormatOptions.match_seen) {
      if (httpFormatOptions.newline)
        fputs("-no-match-", fp);
      else
        fputs("-no-match-\n", fp);
    }

    
    /* Close the block */
    if (httpFormatOptions.newline)
        fputs("] ", fp);
    else
        fputs("]\n", fp);



}

/*
// Removed, used in old solution. 
static size_t clp_message_size(const struct header_chunk* header, const char* ptr){
  return strlen(ptr);
}

*/

struct caputils_protocol protocol_http = {
	.name = "HTTP",
	.size = 0,
	.next_payload = NULL,
	.format = http_format,
	.dump = http_dump,
};
