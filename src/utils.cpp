/*
 * utils.c - various utility functions used in pppd.
 *
 * Copyright (c) 1999-2002 Paul Mackerras. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. The name(s) of the authors of this software must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 3. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Paul Mackerras
 *     <paulus@samba.org>".
 *
 * THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "ppp_opts.h"

#include "ppp_impl.h"

#include "fsm.h"
#include "lcp.h"

#if defined(SUNOS4)
extern char *strerror();
#endif

static void ppp_logit(int level, const char *fmt, va_list args);
static void ppp_log_write(int level, char *buf);


/*
 * ppp_strlcpy - like strcpy/strncpy, doesn't overflow destination buffer,
 * always leaves destination null-terminated (for len > 0).
 */
size_t ppp_strlcpy(char *dest, const char *src, size_t len) {
    size_t ret = strlen(src);

    if (len != 0) {
	if (ret < len)
	    strcpy(dest, src);
	else {
	    strncpy(dest, src, len - 1);
	    dest[len-1] = 0;
	}
    }
    return ret;
}

/*
 * ppp_strlcat - like strcat/strncat, doesn't overflow destination buffer,
 * always leaves destination null-terminated (for len > 0).
 */
size_t ppp_strlcat(char *dest, const char *src, size_t len) {
    size_t dlen = strlen(dest);

    return dlen + ppp_strlcpy(dest + dlen, src, (len > dlen? len - dlen: 0));
}


/*
 * ppp_slprintf - format a message into a buffer.  Like sprintf except we
 * also specify the length of the output buffer, and we handle
 * %m (error message), %v (visible string),
 * %q (quoted string), %t (current time) and %I (IP address) formats.
 * Doesn't do floating-point formats.
 * Returns the number of chars put into buf.
 */
int ppp_slprintf(char *buf, int buflen, const char *fmt, ...) {
    va_list args;
    int n;

    va_start(args, fmt);
    n = ppp_vslprintf(buf, buflen, fmt, args);
    va_end(args);
    return n;
}

/*
 * ppp_vslprintf - like ppp_slprintf, takes a va_list instead of a list of args.
 */
#define OUTCHAR(c)	(buflen > 0? (--buflen, *buf++ = (c)): 0)

int ppp_vslprintf(char *buf, int buflen, const char *fmt, va_list args) {
    int c, i, n;
    int width, prec, fillch;
    int base, len, neg, quoted;
    unsigned long val = 0;
    const char *f;
    char *str, *buf0;
    const unsigned char *p;
    char num[32];

    uint32_t ip;
    static char hexchars[] = "0123456789abcdef";

    buf0 = buf;
    --buflen;
    while (buflen > 0) {
	for (f = fmt; *f != '%' && *f != 0; ++f)
	    ;
	if (f > fmt) {
	    len = f - fmt;
	    if (len > buflen)
		len = buflen;
	    memcpy(buf, fmt, len);
	    buf += len;
	    buflen -= len;
	    fmt = f;
	}
	if (*fmt == 0)
	    break;
	c = *++fmt;
	width = 0;
	prec = -1;
	fillch = ' ';
	if (c == '0') {
	    fillch = '0';
	    c = *++fmt;
	}
	if (c == '*') {
	    width = va_arg(args, int);
	    c = *++fmt;
	} else {
	    while (lwip_isdigit(c)) {
		width = width * 10 + c - '0';
		c = *++fmt;
	    }
	}
	if (c == '.') {
	    c = *++fmt;
	    if (c == '*') {
		prec = va_arg(args, int);
		c = *++fmt;
	    } else {
		prec = 0;
		while (lwip_isdigit(c)) {
		    prec = prec * 10 + c - '0';
		    c = *++fmt;
		}
	    }
	}
	str = nullptr;
	base = 0;
	neg = 0;
	++fmt;
	switch (c) {
	case 'l':
	    c = *fmt++;
	    switch (c) {
	    case 'd':
		val = va_arg(args, long);
		if ((long)val < 0) {
		    neg = 1;
		    val = (unsigned long)-(long)val;
		}
		base = 10;
		break;
	    case 'u':
		val = va_arg(args, unsigned long);
		base = 10;
		break;
	    default:
		OUTCHAR('%');
		OUTCHAR('l');
		--fmt;		/* so %lz outputs %lz etc. */
		continue;
	    }
	    break;
	case 'd':
	    i = va_arg(args, int);
	    if (i < 0) {
		neg = 1;
		val = -i;
	    } else
		val = i;
	    base = 10;
	    break;
	case 'u':
	    val = va_arg(args, unsigned int);
	    base = 10;
	    break;
	case 'o':
	    val = va_arg(args, unsigned int);
	    base = 8;
	    break;
	case 'x':
	case 'X':
	    val = va_arg(args, unsigned int);
	    base = 16;
	    break;

	case 's':
	    str = va_arg(args, char *);
	    break;
	case 'c':
	    num[0] = va_arg(args, int);
	    num[1] = 0;
	    str = num;
	    break;

	case 'I':
	    ip = va_arg(args, uint32_t);
	    ip = lwip_ntohl(ip);
	    ppp_slprintf(num, sizeof(num), "%d.%d.%d.%d", (ip >> 24) & 0xff,
		     (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
	    str = num;
	    break;

	case 'v':		/* "visible" string */
	case 'q':		/* quoted string */
	    quoted = c == 'q';
	    p = va_arg(args, unsigned char *);
	    if (p == NULL)
		p = (const unsigned char *)"<NULL>";
	    if (fillch == '0' && prec >= 0) {
		n = prec;
	    } else {
		n = strlen((const char *)p);
		if (prec >= 0 && n > prec)
		    n = prec;
	    }
	    while (n > 0 && buflen > 0) {
		c = *p++;
		--n;
		if (!quoted && c >= 0x80) {
		    OUTCHAR('M');
		    OUTCHAR('-');
		    c -= 0x80;
		}
		if (quoted && (c == '"' || c == '\\'))
		    OUTCHAR('\\');
		if (c < 0x20 || (0x7f <= c && c < 0xa0)) {
		    if (quoted) {
			OUTCHAR('\\');
			switch (c) {
			case '\t':	OUTCHAR('t');	break;
			case '\n':	OUTCHAR('n');	break;
			case '\b':	OUTCHAR('b');	break;
			case '\f':	OUTCHAR('f');	break;
			default:
			    OUTCHAR('x');
			    OUTCHAR(hexchars[c >> 4]);
			    OUTCHAR(hexchars[c & 0xf]);
			}
		    } else {
			if (c == '\t')
			    OUTCHAR(c);
			else {
			    OUTCHAR('^');
			    OUTCHAR(c ^ 0x40);
			}
		    }
		} else
		    OUTCHAR(c);
	    }
	    continue;

	case 'B':
	    p = va_arg(args, unsigned char *);
	    for (n = prec; n > 0; --n) {
		c = *p++;
		if (fillch == ' ')
		    OUTCHAR(' ');
		OUTCHAR(hexchars[(c >> 4) & 0xf]);
		OUTCHAR(hexchars[c & 0xf]);
	    }
	    continue;
	default:
	    *buf++ = '%';
	    if (c != '%')
		--fmt;		/* so %z outputs %z etc. */
	    --buflen;
	    continue;
	}
	if (base != 0) {
	    str = num + sizeof(num);
	    *--str = 0;
	    while (str > num + neg) {
		*--str = hexchars[val % base];
		val = val / base;
		if (--prec <= 0 && val == 0)
		    break;
	    }
	    switch (neg) {
	    case 1:
		*--str = '-';
		break;
	    case 2:
		*--str = 'x';
		*--str = '0';
		break;
	    default:
		break;
	    }
	    len = num + sizeof(num) - 1 - str;
	} else {
	    len = strlen(str);
	    if (prec >= 0 && len > prec)
		len = prec;
	}
	if (width > 0) {
	    if (width > buflen)
		width = buflen;
	    if ((n = width - len) > 0) {
		buflen -= n;
		for (; n > 0; --n)
		    *buf++ = fillch;
	    }
	}
	if (len > buflen)
	    len = buflen;
	memcpy(buf, str, len);
	buf += len;
	buflen -= len;
    }
    *buf = 0;
    return buf - buf0;
}



/*
 * ppp_print_string - print a readable representation of a string using
 * printer.
 */
void ppp_print_string(const uint8_t *p, int len, void (*printer) (void *, const char *, ...), void *arg) {
    int c;

    printer(arg, "\"");
    for (; len > 0; --len) {
	c = *p++;
	if (' ' <= c && c <= '~') {
	    if (c == '\\' || c == '"')
		printer(arg, "\\");
	    printer(arg, "%c", c);
	} else {
	    switch (c) {
	    case '\n':
		printer(arg, "\\n");
		break;
	    case '\r':
		printer(arg, "\\r");
		break;
	    case '\t':
		printer(arg, "\\t");
		break;
	    default:
		printer(arg, "\\%.3o", (uint8_t)c);
		/* no break */
	    }
	}
    }
    printer(arg, "\"");
}

/*
 * ppp_logit - does the hard work for fatal et al.
 */
static void ppp_logit(int level, const char *fmt, va_list args) {
    char buf[1024];

    ppp_vslprintf(buf, sizeof(buf), fmt, args);
    ppp_log_write(level, buf);
}

static void ppp_log_write(int level, char *buf) {
    ; /* necessary if PPPDEBUG is defined to an empty function */
    ;
    PPPDEBUG(level, ("%s\n", buf) );

}

/*
 * ppp_fatal - log an error message and die horribly.
 */
void ppp_fatal(const char *fmt, ...) {
    va_list pvar;

    va_start(pvar, fmt);
    ppp_logit(LOG_ERR, fmt, pvar);
    va_end(pvar);

    lwip_assert("ppp_fatal", 0);   /* as promised */
}

/*
 * ppp_error - log an error message.
 */
void ppp_error(const char *fmt, ...) {
    va_list pvar;

    va_start(pvar, fmt);
    ppp_logit(LOG_ERR, fmt, pvar);
    va_end(pvar);

}

/*
 * ppp_warn - log a warning message.
 */
void ppp_warn(const char *fmt, ...) {
    va_list pvar;

    va_start(pvar, fmt);
    ppp_logit(LOG_WARNING, fmt, pvar);
    va_end(pvar);
}

/*
 * ppp_notice - log a notice-level message.
 */
void ppp_notice(const char *fmt, ...) {
    va_list pvar;

    va_start(pvar, fmt);
    ppp_logit(LOG_NOTICE, fmt, pvar);
    va_end(pvar);
}

/*
 * ppp_info - log an informational message.
 */
void ppp_info(const char *fmt, ...) {
    va_list pvar;

    va_start(pvar, fmt);
    ppp_logit(LOG_INFO, fmt, pvar);
    va_end(pvar);
}

/*
 * ppp_dbglog - log a debug message.
 */
void ppp_dbglog(const char *fmt, ...) {
    va_list pvar;

    va_start(pvar, fmt);
    ppp_logit(LOG_DEBUG, fmt, pvar);
    va_end(pvar);
}

