#ifndef PREPHOME_CONFIG_H
#define PREPHOME_CONFIG_H

#include <string.h>

#define UNUSED              __attribute__((unused))

#define PREPHOME_DEBUG      0x01	/* be verbose about things */
#define PREPHOME_QUIET      0x02	/* keep quiet about things */

#define LOGIN_DEFS          "/etc/login.defs"
#define UMASK_DEFAULT       "0022"

typedef struct {
  int ctrl;
  const char *umask;
  const char *skeldir;
  const char *storage;
} options_t;

static inline const char *
skip_prefix_len (const char *str, const char *prefix, size_t prefix_len)
{
	return strncmp(str, prefix, prefix_len) ? NULL : str + prefix_len;
}

#define str_skip_prefix(str_, prefix_) skip_prefix_len((str_), (prefix_), sizeof(prefix_) - 1)

#endif /* PREPHOME_CONFIG_H */