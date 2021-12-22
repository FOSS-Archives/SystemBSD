/*
 * Copyright (c) 2014 Ian Sutton <ian@kremlin.cc>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <unistd.h>
#include <limits.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <string.h>

#include <glib/gprintf.h>
#include <glib-unix.h>
#include <glib/gstdio.h>
#include <polkit/polkit.h>

#include "timedated-gen.h"
#include "timedated.h"

#include "../../util.h"

#define TZNAME_MAX PATH_MAX

GPtrArray *timedated_freeable;
Timedate1 *timedated_interf;

GMainLoop *timedated_loop;

guint bus_descriptor;
gboolean dbus_interface_exported; /* reliable because of gdbus operational guarantees */

const gchar *OS_LOCALTIME       = "/etc/localtime";      /* current timezone file */
const gchar *OS_TIMEZONE_PATH   = "/usr/share/zoneinfo"; /* path to system timezone files */

struct timezone_checksum_pair {

    gchar *path;
    gchar *sum;
    gboolean posix;
    gboolean right;
};

static struct timezone_checksum_pair tz_table[5000];

/* --- begin method/property/dbus signal code --- */

static gboolean
on_handle_set_time(Timedate1 *td1_passed_interf,
                   GDBusMethodInvocation *invoc,
                   const gchar *greet,
                   gpointer data) {

    GVariant *params;
    gint64 proposed_time, cur_time;
    const gchar *bus_name;
    gboolean policykit_auth;
    check_auth_result is_authed;
    gboolean relative; /* relative if passed time_t is meant to be added to current time */
    struct timespec *new_time;

    params = g_dbus_method_invocation_get_parameters(invoc);
    g_variant_get(params, "(xbb)", &proposed_time, &relative, &policykit_auth);
    bus_name = g_dbus_method_invocation_get_sender(invoc);

    is_authed = polkit_try_auth(bus_name, "org.freedesktop.timedate1.set-time", policykit_auth);

    switch(is_authed) {

        case AUTHORIZED_NATIVELY:
        case AUTHORIZED_BY_PROMPT:
            break;

        case UNAUTHORIZED_NATIVELY:
        case UNAUTHORIZED_FAILED_PROMPT:
            g_dbus_method_invocation_return_dbus_error(invoc, "org.freedesktop.timedate1.Error.EACCES", "Insufficient permissions to set system time.");
            return FALSE;

        case ERROR_BADBUS:
            g_dbus_method_invocation_return_dbus_error(invoc, "org.freedesktop.timedate1.Error.EFAULT", "Provided bus name is invalid.");
            return FALSE;

        case ERROR_BADACTION:
            g_dbus_method_invocation_return_dbus_error(invoc, "org.freedesktop.timedate1.Error.EFAULT", "Provided action ID is invalid.");
            return FALSE;

        case ERROR_GENERIC:
        default:
            g_dbus_method_invocation_return_dbus_error(invoc, "org.freedesktop.timedate1.Error.ECANCELED", "Failed to set system time for unknown reasons.");
            return FALSE;
    }

    if(!proposed_time) {
        
        timedate1_complete_set_time(td1_passed_interf, invoc);
        return TRUE;

    } else if(relative) {

        cur_time = g_get_real_time();

        if(proposed_time < 0 && cur_time + proposed_time > cur_time) {

            g_dbus_method_invocation_return_dbus_error(invoc, "org.freedesktop.timedate1.Error.EINVAL", "Resultant time out of bounds.");
            return FALSE;

        } else if(proposed_time > 0 && cur_time + proposed_time < cur_time) {

            g_dbus_method_invocation_return_dbus_error(invoc, "org.freedesktop.timedate1.Error.EINVAL", "Resultant time out of bounds.");
            return FALSE;
        }

        new_time = mktimespec(proposed_time);

        if(!clock_settime(CLOCK_REALTIME, new_time)) {

            timedate1_complete_set_time(td1_passed_interf, invoc);
            return TRUE;

        } else {

            g_dbus_method_invocation_return_dbus_error(invoc, "org.freedesktop.timedate1.Error.ECANCELED", "Failed to set system time for unknown reasons.");
            return FALSE;
        }

    } else if(proposed_time > 0) {


        new_time = mktimespec(proposed_time);

        if(!clock_settime(CLOCK_REALTIME, new_time)) {

            timedate1_complete_set_time(td1_passed_interf, invoc);
            return TRUE;

        } else {

            g_dbus_method_invocation_return_dbus_error(invoc, "org.freedesktop.timedate1.Error.ECANCELED", "Failed to set system time for unknown reasons.");
            return FALSE;
        }

    } else {

        g_dbus_method_invocation_return_dbus_error(invoc, "org.freedesktop.timedate1.Error.EINVAL", "Resultant time out of bounds.");
        return FALSE;
    }
}

static gboolean
on_handle_set_timezone(Timedate1 *td1_passed_interf,
                   GDBusMethodInvocation *invoc,
                   const gchar *greet,
                   gpointer data) {

    GVariant *params;
    gchar *proposed_tz;
    const gchar *bus_name;
    gboolean policykit_auth;
    check_auth_result is_authed;

    gchar *tz_target_path;
    struct stat *statbuf;
    extern int errno;

    params = g_dbus_method_invocation_get_parameters(invoc);
    g_variant_get(params, "(sb)", &proposed_tz, &policykit_auth);
    bus_name = g_dbus_method_invocation_get_sender(invoc);

    is_authed = polkit_try_auth(bus_name, "org.freedesktop.timedate1.set-timezone", policykit_auth);

    switch(is_authed) {

        case AUTHORIZED_NATIVELY:
        case AUTHORIZED_BY_PROMPT:
            break;

        case UNAUTHORIZED_NATIVELY:
        case UNAUTHORIZED_FAILED_PROMPT:
            g_dbus_method_invocation_return_dbus_error(invoc, "org.freedesktop.timedate1.Error.EACCES", "Insufficient permissions to set timezone.");
            return FALSE;

        case ERROR_BADBUS:
            g_dbus_method_invocation_return_dbus_error(invoc, "org.freedesktop.timedate1.Error.EFAULT", "Provided bus name is invalid.");
            return FALSE;

        case ERROR_BADACTION:
            g_dbus_method_invocation_return_dbus_error(invoc, "org.freedesktop.timedate1.Error.EFAULT", "Provided action ID is invalid.");
            return FALSE;

        case ERROR_GENERIC:
        default:
            g_dbus_method_invocation_return_dbus_error(invoc, "org.freedesktop.timedate1.Error.ECANCELED", "Failed to set timezone for unknown reasons.");
            return FALSE;
    }

    statbuf        = (struct stat*) calloc(1, sizeof(struct stat));
    tz_target_path = (gchar *) calloc(1, TZNAME_MAX);

    g_ptr_array_add(timedated_freeable, statbuf);
    g_ptr_array_add(timedated_freeable, tz_target_path);

    strlcat(tz_target_path, OS_TIMEZONE_PATH, TZNAME_MAX);
    strlcat(tz_target_path, "/", TZNAME_MAX);
    strlcat(tz_target_path, proposed_tz, TZNAME_MAX);

    if(strstr(tz_target_path, "../")) {

        g_dbus_method_invocation_return_dbus_error(invoc, "org.freedesktop.timedate1.Error.EBADF", "Provided timezone is invalid.");
        return FALSE;
    }

    if(!statbuf)
        return FALSE;

    if(lstat(tz_target_path, statbuf)) {

        switch(errno) {

            case ENOENT:
                g_dbus_method_invocation_return_dbus_error(invoc, "org.freedesktop.timedate1.Error.ENOENT", "Specified timezone does not exist.");
                break;

            default:
                g_dbus_method_invocation_return_dbus_error(invoc, "org.freedesktop.timedate1.Error.EBADF", "Specified timezone is invalid.");
                break;
        }

        return FALSE;
    }
    
    if(!S_ISREG(statbuf->st_mode)) {

        g_dbus_method_invocation_return_dbus_error(invoc, "org.freedesktop.timedate1.Error.EBADF", "Specified path is of an inappropriate type.");
        return FALSE;
    }

    memset(statbuf, 0, sizeof statbuf);

    if(!lstat(OS_LOCALTIME, statbuf))
        if(remove(OS_LOCALTIME))
            return FALSE;

    if(symlink(tz_target_path, OS_LOCALTIME))
        return FALSE;

    
    timedate1_complete_set_timezone(td1_passed_interf, invoc);

    return TRUE;
}

static gboolean
on_handle_set_local_rtc(Timedate1 *td1_passed_interf,
                        GDBusMethodInvocation *invoc,
                        const gchar *greet,
                        gpointer data) {

    g_dbus_method_invocation_return_dbus_error(invoc, "org.freedesktop.timedate1.Error.ENODEV", "Unix RTC must be in UTC.");
    return TRUE;
}

static gboolean
on_handle_set_ntp(Timedate1 *td1_passed_interf,
                  GDBusMethodInvocation *invoc,
                  const gchar *greet,
                  gpointer data) {

    GVariant *params;
    const gchar *bus_name;
    gboolean policykit_auth;
    check_auth_result is_authed;

                                            /* revert to rcctl when 5.7 rolls around */
    gint ntpd_notrunning, ntpd_notenabled; /* this logic flip is due to rcctl returning 0 on success, 
                                             * in this case an error means ntpd is not running or not enabled */
    gboolean proposed_ntpstate;
    GError *sh_errors;

    extern int errno;

    params = g_dbus_method_invocation_get_parameters(invoc);
    g_variant_get(params, "(bb)", &proposed_ntpstate, &policykit_auth);
    bus_name = g_dbus_method_invocation_get_sender(invoc);

    is_authed = polkit_try_auth(bus_name, "org.freedesktop.timedate1.set-ntp", policykit_auth);

    switch(is_authed) {

        case AUTHORIZED_NATIVELY:
        case AUTHORIZED_BY_PROMPT:
            break;

        case UNAUTHORIZED_NATIVELY:
        case UNAUTHORIZED_FAILED_PROMPT:
            g_dbus_method_invocation_return_dbus_error(invoc, "org.freedesktop.timedate1.Error.EACCES", "Insufficient permissions to toggle the NTP daemon.");
            return FALSE;

        case ERROR_BADBUS:
            g_dbus_method_invocation_return_dbus_error(invoc, "org.freedesktop.timedate1.Error.EFAULT", "Provided bus name is invalid.");
            return FALSE;

        case ERROR_BADACTION:
            g_dbus_method_invocation_return_dbus_error(invoc, "org.freedesktop.timedate1.Error.EFAULT", "Provided action ID is invalid.");
            return FALSE;

        case ERROR_GENERIC:
        default:
            g_dbus_method_invocation_return_dbus_error(invoc, "org.freedesktop.timedate1.Error.ECANCELED", "Failed to toggle the NTP daemon for unknown reasons.");
            return FALSE;
    }

    ntpd_notrunning = 0;   /* GLib does not bother asserting the passed return value int to zero */
    ntpd_notenabled = 0;   /* if the program's exit status is also zero, hence this decl.        */

    if((ntpd_notrunning = system("/etc/rc.d/ntpd check > /dev/null 2>&1")) == -1)
        return FALSE;

    if((ntpd_notenabled = system("/etc/rc.d/ntpd status > /dev/null 2>&1")) == -1)
        return FALSE;

    if(proposed_ntpstate) {

        if(ntpd_notrunning)
            system("/etc/rc.d/ntpd -f start > /dev/null 2>&1");

        if(ntpd_notenabled)
            system("/etc/rc.d/ntpd enable > /dev/null 2>&1");

    } else {

        if(!ntpd_notrunning)
            system("/etc/rc.d/ntpd stop > /dev/null 2>&1");

        if(!ntpd_notenabled)
            system("/etc/rc.d/ntpd disable > /dev/null 2>&1");
    }
 
    timedate1_complete_set_ntp(td1_passed_interf, invoc);

    return TRUE; 
}
/* NOTE: you should be using gobject->set_property() for these ! */
const gchar *
our_get_timezone() {

    GStatBuf *stat_zoneinfo;
    gchar *find_cmd, *readlink_path, *ret, *argvp, *hash_to_match;
    gint argcp;
    GError *err;
    struct timezone_checksum_pair tmp;

    find_cmd      = (gchar *)    g_malloc0(2048);
    stat_zoneinfo = (GStatBuf *) g_malloc0(8192);
    err           = (GError *)   g_malloc0(2048);

    if(g_stat(OS_LOCALTIME, stat_zoneinfo)) {

        g_printf("could not read from %s! please symlink or copy a timezone file from %s to %s!\n", OS_LOCALTIME, OS_TIMEZONE_PATH, OS_LOCALTIME);
        ret = NULL;

    } else if(g_file_test(OS_LOCALTIME, G_FILE_TEST_IS_SYMLINK)) {

        readlink_path = g_file_read_link(OS_LOCALTIME, &err);

        gchar *split[2] = { readlink_path, "" };
        tmp = parse_timezone_path(split);

        ret = tmp.path;

        if(readlink_path)
            g_free(readlink_path);

    } else {

        g_printf("%s is not a symlink! attempting to match checksums in %s...\n", OS_LOCALTIME, OS_TIMEZONE_PATH);
        hash_to_match = get_file_sha256(OS_LOCALTIME);

        /* ret = lookup_hash(hash_to_match); */
        return FALSE; /* TODO fix me for real */

        if(hash_to_match)
            g_free(hash_to_match);
    }
 
    return ret;
}

/* Unix time is in UTC. */
gboolean
our_get_local_rtc() { 

    return FALSE; 
}

gboolean
our_get_can_ntp() {
 
    /* ntpd is part of the default install */

    return TRUE;
}

gboolean
our_get_ntp() {
 
    int system_ret;

    system_ret = system("/etc/rc.d/ntpd check > /dev/null 2>&1");

    if(system_ret)
        return FALSE;

    return TRUE;
}

/* undocumented feature present in systemd */
gboolean
our_get_ntpsynchronized() {
 
    gboolean ntp;
    ntp = our_get_ntp();

    return ntp;
}

/* undocumented feature present in systemd */
guint64
our_get_time_usec() {

    guint64 ret = 0;

    return ret;
}

/* undocumented feature present in systemd */
guint64
our_get_rtc_time_usec() {

    guint64 ret = 0;

    return ret;
}

/* --- end method/property/dbus signal code, begin bus/name handlers --- */

static void timedated_on_bus_acquired(GDBusConnection *conn,
                                      const gchar *name,
                                      gpointer user_data) {

    g_printf("got bus/name, exporting %s's interface...\n", name);

    timedated_interf = timedate1_skeleton_new();

    /* attach function pointers to generated struct's method handlers */
    g_signal_connect(timedated_interf, "handle-set-time",     G_CALLBACK(on_handle_set_time),     NULL);
    g_signal_connect(timedated_interf, "handle-set-timezone", G_CALLBACK(on_handle_set_timezone), NULL);
    g_signal_connect(timedated_interf, "handle-set-local-rtc", G_CALLBACK(on_handle_set_local_rtc), NULL);
    g_signal_connect(timedated_interf, "handle-set-ntp",      G_CALLBACK(on_handle_set_ntp),      NULL);

    /* set our properties before export */
    
    timedate1_set_timezone(timedated_interf, our_get_timezone());
    timedate1_set_local_rtc(timedated_interf, our_get_local_rtc());
    timedate1_set_can_ntp(timedated_interf, our_get_can_ntp());
    timedate1_set_ntp(timedated_interf, our_get_ntp());
    timedate1_set_ntpsynchronized(timedated_interf, our_get_ntpsynchronized());
    timedate1_set_time_usec(timedated_interf, our_get_time_usec());
    timedate1_set_rtctime_usec(timedated_interf, our_get_rtc_time_usec());
    
    /* WIP

    timedated_interf->get_timezone        = our_get_timezone();
    timedated_interf->get_local_rtc       = our_get_local_rtc();
    timedated_interf->get_can_ntp         = our_get_can_ntp();
    timedated_interf->get_ntp             = our_get_ntp();
    timedated_interf->get_ntpsynchronized = our_get_ntpsynchronized();
    timedated_interf->get_time_usec       = our_get_time_usec();
    timedated_interf->get_rtctime_usec    = our_get_rtc_time_usec(); */

    if(!g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(timedated_interf),
                                         conn,
                                         "/org/freedesktop/timedate1",
                                         NULL)) {

        g_printf("failed to export %s's interface!\n", name);
        timedated_mem_clean();

    } else {

        dbus_interface_exported = TRUE;
        g_printf("exported %s's interface on the system bus...\n", name);
    }
}

static void timedated_on_name_acquired(GDBusConnection *conn,
                                       const gchar *name,
                                       gpointer user_data) {

   g_printf("success!\n"); 
}

static void timedated_on_name_lost(GDBusConnection *conn,
                                   const gchar *name,
                                   gpointer user_data) {

    if(!conn) {

        g_printf("failed to connect to the system bus while trying to acquire name '%s': either dbus-daemon isn't running or we don't have permission to push names and/or their interfaces to it.\n", name);
        timedated_mem_clean();
    }

    g_print("lost name %s, exiting...\n", name);

    timedated_mem_clean();
}

/* --- end bus/name handlers, begin misc unix functions --- */

/* safe call to clean and then exit
 * this stops our GMainLoop safely before letting main() return */
void timedated_mem_clean() {

    g_printf("exiting...\n");

    if(dbus_interface_exported)
        g_dbus_interface_skeleton_unexport(G_DBUS_INTERFACE_SKELETON(timedated_interf));

     if(g_main_loop_is_running(timedated_loop))
        g_main_loop_quit(timedated_loop);

}

/* wrapper for glib's unix signal handling; called only once if terminating signal is raised against us */
gboolean unix_sig_terminate_handler(gpointer data) {

    g_printf("caught SIGINT/HUP/TERM, exiting\n");

    timedated_mem_clean();
    return G_SOURCE_REMOVE;
}

void set_signal_handlers() {

    /* we don't care about its descriptor, we never need to unregister these */
    g_unix_signal_add(SIGINT,  unix_sig_terminate_handler, NULL);
    g_unix_signal_add(SIGHUP,  unix_sig_terminate_handler, NULL);
    g_unix_signal_add(SIGTERM, unix_sig_terminate_handler, NULL);
}

int main() {

    set_signal_handlers();

    /*if(!build_lookup_table())
        return 1; */

    timedated_loop = g_main_loop_new(NULL, TRUE);
    timedated_freeable = g_ptr_array_new();

     bus_descriptor = g_bus_own_name(G_BUS_TYPE_SYSTEM,
                                    "org.freedesktop.timedate1",
                                    G_BUS_NAME_OWNER_FLAGS_NONE,
                                    timedated_on_bus_acquired,
                                    timedated_on_name_acquired,
                                    timedated_on_name_lost,
                                    NULL,
                                    NULL);

    g_main_loop_run(timedated_loop);
    /* runs until single g_main_loop_quit() call is raised inside <interface>_mem_clean() */
    g_main_loop_unref(timedated_loop);

    /* guaranteed unownable */
    g_bus_unown_name(bus_descriptor);

    /* at this point no operations can occur with our data, it is safe to free it + its container */
    g_ptr_array_free(timedated_freeable, TRUE);

    return 0;
}

static struct timezone_checksum_pair parse_timezone_path(gchar **pair) {

    gchar *prefix_pattern, *right_prefix_pattern, *posix_prefix_pattern, *lean_path;
    GRegex *prefix, *posix, *right;
    GError *err = NULL;
    struct timezone_checksum_pair ret = { NULL, NULL, FALSE, FALSE };

    if(!pair[0])
        return ret;

    prefix_pattern = (gchar *) g_malloc0(4096);
    right_prefix_pattern = (gchar *) g_malloc0(4096);
    posix_prefix_pattern = (gchar *) g_malloc0(4096);

    g_sprintf(prefix_pattern, "%s/", OS_TIMEZONE_PATH);
    g_sprintf(posix_prefix_pattern, "%s/posix/", OS_TIMEZONE_PATH);
    g_sprintf(right_prefix_pattern, "%s/right/", OS_TIMEZONE_PATH);

    prefix = g_regex_new(prefix_pattern, 0, 0, &err);
    posix  = g_regex_new(posix_prefix_pattern, 0, 0, &err);
    right  = g_regex_new(right_prefix_pattern, 0, 0, &err);

    if(g_regex_match_full(posix, pair[0], -1, 0, G_REGEX_MATCH_NOTEMPTY, NULL, NULL)) {

        ret.posix = TRUE;
        lean_path = g_regex_replace_literal(posix, pair[0], -1, 0, "", G_REGEX_MATCH_NOTEMPTY, NULL);

    } else if(g_regex_match_full(right, pair[0], -1, 0, G_REGEX_MATCH_NOTEMPTY, NULL, NULL)) {
 
       ret.right = TRUE;
       lean_path = g_regex_replace_literal(right, pair[0], -1, 0, "", G_REGEX_MATCH_NOTEMPTY, NULL);

    } else
        lean_path = g_regex_replace_literal(prefix, pair[0], -1, 0, "", G_REGEX_MATCH_NOTEMPTY, NULL);

    ret.path = lean_path;

    ret.sum = g_malloc0(256);
    g_strlcpy(ret.sum, pair[1], 66);

    g_regex_unref(prefix);
    g_regex_unref(right);
    g_regex_unref(posix);

    return ret;
}

/* TODO need to deconstruct tz_table on exit
static gboolean build_lookup_table() {

        gchar *find_cmd, **map_pairs, *find_output, *path_buf, *sum_buf, **entry_buf;
        GError *err;
        gboolean ret;
        gint i;

        i   = 0;
        err = NULL;
        ret = TRUE;

        find_cmd    = (gchar *) g_malloc0(4096);
        find_output = (gchar *) g_malloc0(1000000);

        g_sprintf(find_cmd, "/bin/sh -c \"find %s -type f -exec cksum -a sha256 {} \\; | sed -E 's/SHA256 \\(//g' | sed -E 's/\\) = /=/g'\"", OS_TIMEZONE_PATH);

        if(!g_spawn_command_line_sync(find_cmd, &find_output, NULL, NULL, &err)) {

            g_printf("error running `%s`\n", find_cmd);
            ret = FALSE;
        }

        map_pairs = g_strsplit(find_output, "\n", INT_MAX);

        while(map_pairs[i] && (entry_buf = g_strsplit(map_pairs[i], "=", INT_MAX))) {

            tz_table[i] = parse_timezone_path(entry_buf);

            g_strfreev(entry_buf);
            i++;
        }

        g_free(find_output);
        g_free(find_cmd);
        g_free(map_pairs);

        return ret;
}

static gchar *lookup_hash(gchar *hash) {

    gint i = 0;

    while(tz_table[i].sum)
        if(!g_strcmp0(tz_table[i].sum, hash))
            return tz_table[i].path;
        else
            i++;

    return NULL;
}*/

/* takes number of microseconds since epoch and returns a 
 * ptr to a timespec suitable to be passed to clock_settime(3)
 */
static struct timespec* mktimespec(gint64 us) {

    long nanoseconds;
    time_t seconds;

    gint64 div_buf_remainder, div_buf_s, div_buf_ns;
    struct timespec *ret;

    div_buf_s         = (us / 1000000); /* us / 10^6 = s */
    div_buf_remainder = (us % 1000000); /* fraction of second lost from prev. line */
    div_buf_ns        = div_buf_remainder * 1000; /* us * 10^3 = ns */

    seconds     = (time_t) div_buf_s; /* porting note: most systems use 32 bit time, adjust accordingly */
    nanoseconds = (long)   div_buf_ns;

    ret = (struct timespec *) calloc(1, sizeof(struct timespec));

    ret->tv_sec  = seconds;
    ret->tv_nsec = nanoseconds;

    g_ptr_array_add(timedated_freeable, ret);

    return ret;
}
