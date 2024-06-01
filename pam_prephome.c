#include <sys/stat.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

#include "prephome_config.h"



void
parse_args (const pam_handle_t *pamh, int flags, int argc, const char **argv, options_t *opt)
{
    opt->ctrl = 0;
    opt->umask = NULL;
    opt->skeldir = "/etc/skel";
    opt->storage = "/storage";

    if ((flags & PAM_SILENT) == PAM_SILENT)
    {
        opt->ctrl |= PREPHOME_QUIET;
    }

    for (; argc-- > 0; ++argv)
    {
        const char *str;

        if (!strcmp(*argv, "silent"))
        {
            opt->ctrl |= PREPHOME_QUIET;
        }
        else if (!strcmp(*argv, "debug"))
        {
            opt->ctrl |= PREPHOME_DEBUG;
        }
        else if ((str = str_skip_prefix(*argv, "umask=")) != NULL)
        {
            opt->umask = str;
        }
        else if ((str = str_skip_prefix(*argv, "skel=")) != NULL)
        {
            opt->skeldir = str;
        }
        else if ((str = str_skip_prefix(*argv, "storage=")) != NULL)
        {
            opt->storage = str;
        }
        else
        {
            pam_syslog(pamh, LOG_ERR, "Unknown Option: %s", *argv);
        }
    }

    return;
}

int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int retval;
    options_t opt;
    const void *user;
    const struct passwd *pwd;
    struct stat St;
    
    parse_args(pamh, flags, argc, argv, &opt);
}

int
pam_sm_close_session (pam_handle_t *pamh UNUSED, int flags UNUSED, int argc UNUSED, const char **argv UNUSED)
{
    return PAM_SUCCESS;
}