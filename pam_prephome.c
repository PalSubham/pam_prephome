#define _POSIX_C_SOURCE 200809L

#include <sys/stat.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
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
        char *str;

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

static bool
is_home_owner (const struct stat *St, const struct passwd *pwd)
{
    return St->st_uid == pwd->pw_uid && St->st_gid == pwd->pw_gid;
}

static bool
is_home_permission (const pam_handle_t *pamh, const struct stat *St, const options_t *opt)
{   
    char *login_umask = NULL;
    char *login_homemode = NULL;
    bool result;

    if (opt->umask == NULL)
    {
        login_umask = pam_modutil_search_key(pamh, LOGIN_DEFS, "UMASK");
        login_homemode = pam_modutil_search_key(pamh, LOGIN_DEFS, "HOME_MODE");

        if (login_homemode == NULL)
        {
            if (login_umask != NULL)
            {
                login_homemode = umask_to_mode(login_umask);
            }
            else
            {
                login_homemode = umask_to_mode(UMASK_DEFAULT);
            }
        }
    }
    else
    {
        login_homemode = umask_to_mode(opt->umask);
    }

    result = St->st_mode & 0777 == (int) strtoul(login_homemode, NULL, 8);

    free(login_umask);
    free(login_homemode);

    return result;
}

static bool
is_home_ok (const pam_handle_t *pamh, const struct stat *St, const struct passwd *pwd, const options_t *opt)
{
    return S_ISDIR(St->st_mode) && is_home_owner(St, pwd) && is_home_permission(pamh, St, opt);
}

static int
create_homes (pam_handle_t *pamh, options_t *opt, const char *user, const struct passwd *pwd)
{
    struct stat St_home, St_storage;
    char *storage;
    int home_status, storage_status;

    if ((home_status = stat(pwd->pw_dir, &St_home)) == 0)
    {
        if (!is_home_ok(pamh, &St_home, pwd, &opt))
        {
            pam_syslog(pamh, LOG_ERR, "Something exists at home directory location, not touching it");
            return PAM_ERROR_MSG;
        }
    }

    storage = (char *) malloc(strlen(opt->storage) + strlen(pwd->pw_dir) + 1);
    if (storage == NULL)
    {
        pam_syslog(pamh, LOG_ERR, "Cannot allocate memory for storage directory");
        return PAM_BUF_ERR;
    }
    strcpy(storage, opt->storage);
    strcat(storage, pwd->pw_dir);

    if ((storage_status = stat((const char *)storage, &St_storage)) == 0)
    {
        if (!is_home_ok(pamh, &St_storage, pwd, &opt))
        {
            pam_syslog(pamh, LOG_ERR, "Something exists at storage directory location, not touching it");
            return PAM_ERROR_MSG;
        }
    }

    free(storage);
}

int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int retval, creation = 0x00;
    options_t opt;
    void *user;
    struct passwd *pwd;
    struct stat St_home, St_storage;
    char *storage;
    
    parse_args(pamh, flags, argc, argv, &opt);

    /* get username */
    retval = pam_get_item(pamh, PAM_USER, &user);
    if (retval != PAM_SUCCESS || user == NULL || *(const char *) user == '\0')
    {
        pam_syslog(pamh, LOG_ERR, "Cannot obtain username");
        return PAM_USER_UNKNOWN;
    }

    /* get user info */
    pwd = pam_modutil_getpwnam(pamh, (const char *)user);
    if (pwd == NULL)
    {
        pam_syslog(pamh, LOG_ERR, "User unknown.");
        return PAM_USER_UNKNOWN;
    }

    /* stat home and storage directory */
    storage = (char *) malloc(strlen(opt.storage) + strlen(pwd->pw_dir) + 1);
    if (storage == NULL)
    {
        pam_syslog(pamh, LOG_ERR, "Cannot allocate memory for storage directory");
        return PAM_BUF_ERR;
    }
    strcpy(storage, opt.storage);
    strcat(storage, pwd->pw_dir);

    if (stat(pwd->pw_dir, &St_home) == 0 && is_home_ok(pamh, &St_home, pwd, &opt) && stat((const char *)storage, &St_storage) == 0 && is_home_ok(pamh, &St_storage, pwd, &opt))
    {
        if (opt.ctrl & PREPHOME_DEBUG)
        {
            pam_syslog(pamh, LOG_INFO, "Home directory %s & storage directory %s already exists and are ok", pwd->pw_dir, storage);
        }
        return PAM_SUCCESS;
    }

    free(storage);
    
    /* else make things correct */
    return create_homes(pamh, &opt, (const char *) user, &pwd);
}

int
pam_sm_close_session (pam_handle_t *pamh UNUSED, int flags UNUSED, int argc UNUSED, const char **argv UNUSED)
{
    return PAM_SUCCESS;
}