/*  =========================================================================
    assets - Cache of assets

    Copyright (C) 2014 - 2020 Eaton

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
    =========================================================================
*/

/*
@header
    assets - Cache of assets
@discuss
@end
*/

#include "fty_discovery_classes.h"

//  Structure of our class

struct _assets_t {
    zhashx_t *assets;
    int64_t lastupdate;
};


//  --------------------------------------------------------------------------
//  Create a new assets

assets_t *
assets_new (void)
{
    assets_t *self = (assets_t *) zmalloc (sizeof (assets_t));
    assert (self);
    //  Initialize class properties here
    self->assets = zhashx_new();
    zhashx_set_destructor (self->assets, reinterpret_cast<void (*)(void**)>(fty_proto_destroy));
    self->lastupdate = zclock_mono ();
    return self;
}


//  --------------------------------------------------------------------------
//  Destroy the assets

void
assets_destroy (assets_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        assets_t *self = *self_p;
        //  Free class properties here
        zhashx_destroy (&self->assets);
        //  Free object itself
        free (self);
        *self_p = NULL;
    }
}

//  --------------------------------------------------------------------------
//  Put one asset into cache

void
assets_put (assets_t *self, fty_proto_t **msg_p)
{
    if (!self || !msg_p || !*msg_p) return;

    fty_proto_t *msg = *msg_p;
    const char *operation = fty_proto_operation (msg);
    const char *iname = fty_proto_name (msg);
    if (!operation || !iname) {
        // malformed message
        fty_proto_destroy (msg_p);
        return;
    }
    if (streq (operation, "create") || streq (operation, "update")) {
        // create, update
        if (! zhashx_lookup (self->assets, iname)) {
            // new for us
            self->lastupdate = zclock_mono ();
        }
        zhashx_update (self->assets, iname, msg);
        *msg_p = NULL;
        return;
    }
    else if (streq (operation, "delete")) {
        // delete
        zhashx_delete (self->assets, iname);
        fty_proto_destroy (msg_p);
        self->lastupdate = zclock_mono ();
        return;
    }
    fty_proto_destroy (msg_p);
}

bool
s_assets_has_attribute (fty_proto_t *asset, const char *key, const char *value)
{
    // try whether exact key exists
    {
        const char *avalue = fty_proto_ext_string (asset, key, NULL);
        if (avalue) return streq (avalue, value);
    }
    // try indexed key
    int idx = 1;
    while (true) {
        char *ikey = zsys_sprintf ("%s.%i", key, idx);
        const char *avalue = fty_proto_ext_string (asset, ikey, NULL);
        zstr_free (&ikey);
        if (!avalue) return false;
        if (streq (avalue, value)) return true;
        ++idx;
    }
}

//  --------------------------------------------------------------------------
//  Find asset by ext attribute

fty_proto_t *
assets_find (assets_t *self, const char *key, const char *value)
{
    if (!self || !key || !*value) return NULL;

    fty_proto_t *asset = static_cast<fty_proto_t *>(zhashx_first (self->assets));
    while (asset) {
        if (s_assets_has_attribute (asset, key, value)) {
            return asset;
        }
        asset = static_cast<fty_proto_t *> (zhashx_next (self->assets));
    }
    return NULL;
}

//  --------------------------------------------------------------------------
//  return the zclock_mono time in ms when last change happened (create or
//  delete, not update)

int64_t
assets_last_change (assets_t *self)
{
    if (!self) return 0;
    return self->lastupdate;
}

//  --------------------------------------------------------------------------
//  Self test of this class

void
assets_test (bool /* verbose */)
{
    printf (" * assets: ");

    //  @selftest
    assets_t *self = assets_new ();
    assert (self);

    fty_proto_t *msg =  fty_proto_new (FTY_PROTO_ASSET);
    fty_proto_set_name (msg, "%s", "ups");
    fty_proto_set_operation (msg, "%s", "create");
    fty_proto_aux_insert (msg, "type", "%s", "device");
    fty_proto_aux_insert (msg, "subtype", "%s", "ups");
    fty_proto_ext_insert (msg, "ip.1", "%s", "127.0.0.1");
    fty_proto_ext_insert (msg, "ip.2", "%s", "127.0.0.2");
    fty_proto_ext_insert (msg, "name", "%s", "my-nice-name");
    assets_put (self, &msg);

    assert (assets_find (self, "name", "my-nice-name"));
    assert (assets_find (self, "name", "bad name") == NULL);
    assert (assets_find (self, "ip", "127.0.0.1"));
    assert (assets_find (self, "ip", "127.0.0.2"));
    assert (assets_find (self, "ip", "127.0.0.3") == NULL);
    assets_destroy (&self);
    //  @end
    printf ("OK\n");
}
