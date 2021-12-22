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

#include <sys/param.h>
#include <string.h>

#include <glib/gprintf.h>
#include <glib-unix.h>
#include <polkit/polkit.h>

#include "localed-gen.h"
#include "localed.h"

#include "../../util.h"

GPtrArray *localed_freeable;
Locale1 *localed_interf;

GMainLoop *localed_loop;

guint bus_descriptor;
gboolean dbus_interface_exported; /* reliable because of gdbus operational guarantees */

/* --- begin method/property/dbus signal code --- */

static gboolean
on_handle_set_locale(Locale1 *hn1_passed_interf,
                     GDBusMethodInvocation *invoc,
                     const gchar *greet,
                     gpointer data) {
    return FALSE;
}

static gboolean
on_handle_set_v_console_keyboard(Locale1 *hn1_passed_interf,
                                 GDBusMethodInvocation *invoc,
                                 const gchar *greet,
                                 gpointer data) {
    return FALSE;
}

static gboolean
on_handle_set_x11_keyboard(Locale1 *hn1_passed_interf,
                           GDBusMethodInvocation *invoc,
                           const gchar *greet,
                           gpointer data) {
    return FALSE;
}

const gchar * const *
our_get_locale() {
 
    const gchar * const *ret = NULL; 

    return ret;
}

const gchar *
our_get_v_console_keymap() {
 
    return "";
}

const gchar *
our_get_v_console_keymap_toggle() {
 
    return "";
}

const gchar *
our_get_x11_layout() {
 
    return "";
}

const gchar *
our_get_x11_model() {
 
    return "";
}

const gchar *
our_get_x11_variant() {
 
    return "";
}

const gchar *
our_get_x11_options() {
 
    return "";
}


/* --- end method/property/dbus signal code, begin bus/name handlers --- */

static void localed_on_bus_acquired(GDBusConnection *conn,
                                    const gchar *name,
                                    gpointer user_data) {

    g_printf("got bus/name, exporting %s's interface...\n", name);
 
    localed_interf = locale1_skeleton_new();

    /* attach function pointers to generated struct's method handlers */
    g_signal_connect(localed_interf, "handle-set-locale", G_CALLBACK(on_handle_set_locale), NULL);
    g_signal_connect(localed_interf, "handle-set-vconsole-keyboard", G_CALLBACK(on_handle_set_v_console_keyboard), NULL);
    g_signal_connect(localed_interf, "handle-set-x11-keyboard", G_CALLBACK(on_handle_set_x11_keyboard), NULL);

    /* set our properties before export */
    locale1_set_locale(localed_interf, our_get_locale());
    locale1_set_vconsole_keymap(localed_interf, our_get_v_console_keymap());
    locale1_set_vconsole_keymap_toggle(localed_interf, our_get_v_console_keymap_toggle());
    locale1_set_x11_layout(localed_interf, our_get_x11_layout());
    locale1_set_x11_model(localed_interf, our_get_x11_model());
    locale1_set_x11_variant(localed_interf, our_get_x11_variant());
    locale1_set_x11_options(localed_interf, our_get_x11_options());

    if(!g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(localed_interf),
                                         conn,
                                         "/org/freedesktop/locale1",
                                         NULL)) {

        g_printf("failed to export %s's interface!\n", name);
        localed_mem_clean();

    } else {

        dbus_interface_exported = TRUE;
        g_printf("exported %s's interface on the system bus...\n", name);
    }
}

static void localed_on_name_acquired(GDBusConnection *conn,
                                     const gchar *name,
                                     gpointer user_data) {

    g_printf("success!\n");
}

static void localed_on_name_lost(GDBusConnection *conn,
                                   const gchar *name,
                                   gpointer user_data) {

    if(!conn) {

        g_printf("failed to connect to the system bus while trying to acquire name '%s': either dbus-daemon isn't running or we don't have permission to push names and/or their interfaces to it.\n", name);
        localed_mem_clean();
    }

    g_print("lost name %s, exiting...\n", name);

    localed_mem_clean();
}

/* --- end bus/name handlers, begin misc unix functions --- */

/* safe call to clean and then exit
 * this stops our GMainLoop safely before letting main() return */
void localed_mem_clean() {

    g_printf("exiting...\n");

    if(dbus_interface_exported)
        g_dbus_interface_skeleton_unexport(G_DBUS_INTERFACE_SKELETON(localed_interf));

    if(g_main_loop_is_running(localed_loop))
        g_main_loop_quit(localed_loop);

}

/* wrapper for glib's unix signal handling; called only once if terminating signal is raised against us */
gboolean unix_sig_terminate_handler(gpointer data) {

    g_printf("caught SIGINT/HUP/TERM, exiting\n");

    localed_mem_clean();
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

    localed_loop = g_main_loop_new(NULL, TRUE);
    localed_freeable = g_ptr_array_new();

     bus_descriptor = g_bus_own_name(G_BUS_TYPE_SYSTEM,
                                    "org.freedesktop.locale1",
                                    G_BUS_NAME_OWNER_FLAGS_NONE,
                                    localed_on_bus_acquired,
                                    localed_on_name_acquired,
                                    localed_on_name_lost,
                                    NULL,
                                    NULL);

    g_main_loop_run(localed_loop);
    /* runs until single g_main_loop_quit() call is raised inside <interface>_mem_clean() */
    g_main_loop_unref(localed_loop);

    /* guaranteed unownable */
    g_bus_unown_name(bus_descriptor);

    /* at this point no operations can occur with our data, it is safe to free it + its container */
    g_ptr_array_free(localed_freeable, TRUE);

    return 0;
}
