

#include "def.h"
#include <cstring>
#include <process.h>


/**
 * Convert an uint16_t from host- to network byte order.
 *
 * @param n uint16_t in host byte order
 * @return n in network byte order
 */
uint16_t lwip_htons(const uint16_t n) { return PpHtons(n); }

uint16_t lwip_ntohs(const uint16_t n) { return PpNtohs(n); }


uint32_t lwip_ntohl(const uint32_t n) { return PpNtohl(n); }

int lwip_getpid()
{
    #if defined _MSC_VER 
        return _getpid();
    #endif
}


/**
 * Convert an uint32_t from host- to network byte order.
 *
 * @param n uint32_t in host byte order
 * @return n in network byte order
 */
uint32_t lwip_htonl(const uint32_t n) { return PP_HTONL(n); }




/**
 * @ingroup sys_nonstandard
 * lwIP default implementation for strnstr() non-standard function.
 * This can be \#defined to strnstr() depending on your platform port.
 */
char *lwip_strnstr(char *buffer, char *token, const size_t n) {
    const auto tokenlen = strlen(token);
  if (tokenlen == 0) {
      return buffer;
  }
  for (auto p = buffer; *p && (p + tokenlen <= buffer + n); p++) {
    if ((*p == *token) && (strncmp(p, token, tokenlen) == 0)) {
        return p;
    }
  }
  return nullptr;
}


/**
 * @ingroup sys_nonstandard
 * lwIP default implementation for stricmp() non-standard function.
 * This can be \#defined to stricmp() depending on your platform port.
 */
int lwip_stricmp(const char *str1, const char *str2) {
  char c1, c2;

  do {
    c1 = *str1++;
    c2 = *str2++;
    if (c1 != c2) {
      char c1_upc = c1 | 0x20;
      if ((c1_upc >= 'a') && (c1_upc <= 'z')) {
        /* characters are not equal an one is in the alphabet range:
        downcase both chars and check again */
        char c2_upc = c2 | 0x20;
        if (c1_upc != c2_upc) {
          /* still not equal */
          /* don't care for < or > */
          return 1;
        }
      } else {
        /* characters are not equal but none is in the alphabet range */
        return 1;
      }
    }
  } while (c1 != 0);
  return 0;
}



/**
 * @ingroup sys_nonstandard
 * lwIP default implementation for strnicmp() non-standard function.
 * This can be \#defined to strnicmp() depending on your platform port.
 */
int lwip_strnicmp(const char *str1, const char *str2, size_t len) {
  char c1, c2;

  do {
    c1 = *str1++;
    c2 = *str2++;
    if (c1 != c2) {
      char c1_upc = c1 | 0x20;
      if ((c1_upc >= 'a') && (c1_upc <= 'z')) {
        /* characters are not equal an one is in the alphabet range:
        downcase both chars and check again */
        char c2_upc = c2 | 0x20;
        if (c1_upc != c2_upc) {
          /* still not equal */
          /* don't care for < or > */
          return 1;
        }
      } else {
        /* characters are not equal but none is in the alphabet range */
        return 1;
      }
    }
    len--;
  } while ((len != 0) && (c1 != 0));
  return 0;
}



/**
 * @ingroup sys_nonstandard
 * lwIP default implementation for itoa() non-standard function.
 * This can be \#defined to itoa() or snprintf(result, bufsize, "%d", number)
 * depending on your platform port.
 */
void lwip_itoa(char *result, size_t bufsize, int number) {
  char *res = result;
  char *tmp = result + bufsize - 1;
  int n = (number >= 0) ? number : -number;

  /* handle invalid bufsize */
  if (bufsize < 2) {
    if (bufsize == 1) {
      *result = 0;
    }
    return;
  }

  /* First, add sign */
  if (number < 0) {
    *res++ = '-';
  }
  /* Then create the string from the end and stop if buffer full,
     and ensure output string is zero terminated */
  *tmp = 0;
  while ((n != 0) && (tmp > res)) {
    char val = (char)('0' + (n % 10));
    tmp--;
    *tmp = val;
    n = n / 10;
  }
  if (n) {
    /* buffer is too small */
    *result = 0;
    return;
  }
  if (*tmp == 0) {
    /* Nothing added? */
    *res++ = '0';
    *res++ = 0;
    return;
  }
  /* move from temporary buffer to output buffer (sign is not moved) */
  memmove(res, tmp, (size_t)((result + bufsize) - tmp));
}
