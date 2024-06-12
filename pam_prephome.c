#include <sys/stat.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

#include "prephome_config.h"


static void
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

static char *
umask_to_mode (const char *umask)
{
    char str_mode[5];

    (void) snprintf(str_mode, sizeof(str_mode), "0%o", 0777 & ~strtoul(umask, NULL, 8));
    return strdup((const char *) str_mode);
}

static int
create_homes (pam_handle_t *pamh, options_t *opt, const char *user, const struct passwd *pwd)
{

}

int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int retval;
    options_t opt;
    const void *user;
    const struct passwd *pwd;
    struct stat St;
    char *storage;
    
    parse_args(pamh, flags, argc, argv, &opt);

    /* get username */
    retval = pam_get_item(pamh, PAM_USER, &user);
    if (retval != PAM_SUCCESS || user == NULL || *(const char *)user == '\0')
    {
        pam_syslog(pamh, LOG_NOTICE, "Cannot obtain username");
        return PAM_USER_UNKNOWN;
    }

    /* get password */
    pwd = pam_modutil_getpwnam(pamh, (const char *)user);
    if (pwd == NULL)
    {
        pam_syslog(pamh, LOG_NOTICE, "User unknown.");
        return PAM_USER_UNKNOWN;
    }

    /* stat home and storage directory */
    strcpy(storage, opt.storage);
    strcat(storage, pwd->pw_dir);
    if (stat(pwd->pw_dir, &St) == 0 && stat((const char *)storage, &St) == 0)
    {
        if (opt.ctrl & PREPHOME_DEBUG)
        {
            pam_syslog(pamh, LOG_DEBUG, "Home directory %s & storage directory %s already exists", pwd->pw_dir, storage);
        }
        return PAM_SUCCESS;
    }

    return create_homes(pamh, &opt, user, &pwd);
}

int
pam_sm_close_session (pam_handle_t *pamh UNUSED, int flags UNUSED, int argc UNUSED, const char **argv UNUSED)
{
    return PAM_SUCCESS;
}