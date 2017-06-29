/*  =========================================================================
    fty_uuid - UUID generating

    Copyright (C) 2014 - 2017 Eaton

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
    fty_uuid - UUID generating
@discuss
@end
*/

#include "fty_discovery_classes.h"
#include  <openssl/sha.h>
//  Structure of our class

struct _fty_uuid_t {
    zuuid_t *uuid;     //  Declare class properties here
};

// EATON UUID namespace
// printf 'genepibiosipm_converge' | sha1sum | sed 's,^\(........\)\(....\)\(....\)\(....\)\(............\).*$,\1-\2-\3-\4\-\5,'
// #define EATON_NS "933d6c80-dea9-8c6b-d111-8b3b46a181f1"
#define EATON_NS "\x93\x3d\x6c\x80\xde\xa9\x8c\x6b\xd1\x11\x8b\x3b\x46\xa1\x81\xf1"

//  --------------------------------------------------------------------------
//  Create a new fty_uuid

fty_uuid_t *
fty_uuid_new (void)
{
    fty_uuid_t *self = (fty_uuid_t *) zmalloc (sizeof (fty_uuid_t));
    assert (self);
    //  Initialize class properties here
    self->uuid = zuuid_new ();
    return self;
}

unsigned char *fty_sha1 (const char *data)
{
    if (! data) return NULL;

    unsigned char *hash = (unsigned char *) zmalloc (SHA_DIGEST_LENGTH);
    memset (hash, 0, SHA_DIGEST_LENGTH);
    SHA1((unsigned char*)data, strlen (data), hash);
    return hash;
}

//  --------------------------------------------------------------------------
//  Calculate UUID v5 in EATON namespace base on manufacturer, model and serial number

const char*
fty_uuid_calculate (fty_uuid_t *self, const char *mfr, const char *model, const char *serial)
{
    if (! self || !mfr || !model || !serial) {
        return "ffffffff-ffff-ffff-ffff-ffffffffffff";
    }
    char *src = zsys_sprintf ("%s%s%s%s", EATON_NS, mfr, model, serial);
    unsigned char *hash = fty_sha1(src);

    hash[6] &= 0x0F;
    hash[6] |= 0x50;
    hash[8] &= 0x3F;
    hash[8] |= 0x80;

    zuuid_set (self->uuid, hash);
    zstr_free ((char **)&hash);
    zstr_free (&src);
    return zuuid_str_canonical (self->uuid);
}

//  --------------------------------------------------------------------------
//  Generate random UUID

const char*
fty_uuid_generate (fty_uuid_t *self)
{
    zuuid_destroy (&self->uuid);
    self->uuid = zuuid_new ();
    return zuuid_str_canonical (self->uuid);
}

//  --------------------------------------------------------------------------
//  destroy the fty_uuid

void
fty_uuid_destroy (fty_uuid_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        fty_uuid_t *self = *self_p;
        //  Free class properties here
        zuuid_destroy (&self->uuid);
        //  Free object itself
        free (self);
        *self_p = NULL;
    }
}

//  --------------------------------------------------------------------------
//  Self test of this class

void
fty_uuid_test (bool verbose)
{
    printf (" * fty_uuid: ");

    //  @selftest
    //  Simple create/destroy test

    fty_uuid_t *self = fty_uuid_new ();
    assert (self);
    const char *id = fty_uuid_calculate (self, NULL, NULL, NULL);
    assert (streq (id, "ffffffff-ffff-ffff-ffff-ffffffffffff"));
    id = fty_uuid_calculate (self, "EATON", "IPC3000", "LA71042052");
    assert (streq (id,  "c7cc6ffe-f36f-55ee-b5d4-3e40a2fe08a3"));
    fty_uuid_destroy (&self);
    //  @end
    printf ("OK\n");
}
