/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/*
 *  (C) Copyright IBM Corp. 1999 All Rights Reserved.
 *  Copyright 1997 The Open Group Research Institute.  All rights reserved.
 */

package ullink.security.krb5.internal;

import ullink.security.util.DerOutputStream;
import ullink.security.util.DerValue;

import java.io.IOException;
import java.util.Vector;

/**
 * Implements the ASN.1 KrbCredInfo type.
 *
 * <xmp>
 * KrbCredInfo  ::= SEQUENCE {
 *      key             [0] EncryptionKey,
 *      prealm          [1] Realm OPTIONAL,
 *      pname           [2] PrincipalName OPTIONAL,
 *      flags           [3] TicketFlags OPTIONAL,
 *      authtime        [4] KerberosTime OPTIONAL,
 *      starttime       [5] KerberosTime OPTIONAL,
 *      endtime         [6] KerberosTime OPTIONAL,
 *      renew-till      [7] KerberosTime OPTIONAL,
 *      srealm          [8] Realm OPTIONAL,
 *      sname           [9] PrincipalName OPTIONAL,
 *      caddr           [10] HostAddresses OPTIONAL
 * }
 * </xmp>
 *
 * <p>
 * This definition reflects the Network Working Group RFC 4120
 * specification available at
 * <a href="http://www.ietf.org/rfc/rfc4120.txt">
 * http://www.ietf.org/rfc/rfc4120.txt</a>.
 */

public class KrbCredInfo {
    public ullink.security.krb5.EncryptionKey key;
    public ullink.security.krb5.Realm prealm; //optional
    public ullink.security.krb5.PrincipalName pname; //optional
    public ullink.security.krb5.internal.TicketFlags flags; //optional
    public ullink.security.krb5.internal.KerberosTime authtime; //optional
    public ullink.security.krb5.internal.KerberosTime starttime; //optional
    public ullink.security.krb5.internal.KerberosTime endtime; //optional
    public ullink.security.krb5.internal.KerberosTime renewTill; //optional
    public ullink.security.krb5.Realm srealm; //optional
    public ullink.security.krb5.PrincipalName sname; //optional
    public ullink.security.krb5.internal.HostAddresses caddr; //optional

    private KrbCredInfo() {
    }

    public KrbCredInfo(
                       ullink.security.krb5.EncryptionKey new_key,
                       ullink.security.krb5.Realm new_prealm,
                       ullink.security.krb5.PrincipalName new_pname,
                       ullink.security.krb5.internal.TicketFlags new_flags,
                       ullink.security.krb5.internal.KerberosTime new_authtime,
                       ullink.security.krb5.internal.KerberosTime new_starttime,
                       ullink.security.krb5.internal.KerberosTime new_endtime,
                       ullink.security.krb5.internal.KerberosTime new_renewTill,
                       ullink.security.krb5.Realm new_srealm,
                       ullink.security.krb5.PrincipalName new_sname,
                       ullink.security.krb5.internal.HostAddresses new_caddr
                           ) {
        key = new_key;
        prealm = new_prealm;
        pname = new_pname;
        flags = new_flags;
        authtime = new_authtime;
        starttime = new_starttime;
        endtime = new_endtime;
        renewTill = new_renewTill;
        srealm = new_srealm;
        sname = new_sname;
        caddr = new_caddr;
    }

    /**
     * Constructs a KrbCredInfo object.
     * @param encoding a Der-encoded data.
     * @exception ullink.security.krb5.Asn1Exception if an error occurs while decoding an ASN1 encoded data.
     * @exception IOException if an I/O error occurs while reading encoded data.
     * @exception ullink.security.krb5.RealmException if an error occurs while parsing a Realm object.
     */
    public KrbCredInfo(DerValue encoding)
        throws ullink.security.krb5.Asn1Exception, IOException, ullink.security.krb5.RealmException {
        if (encoding.getTag() != DerValue.tag_Sequence) {
            throw new ullink.security.krb5.Asn1Exception(Krb5.ASN1_BAD_ID);
        }
        prealm = null;
        pname = null;
        flags = null;
        authtime = null;
        starttime = null;
        endtime = null;
        renewTill = null;
        srealm = null;
        sname = null;
        caddr = null;
        key = ullink.security.krb5.EncryptionKey.parse(encoding.getData(), (byte) 0x00, false);
        if (encoding.getData().available() > 0)
            prealm = ullink.security.krb5.Realm.parse(encoding.getData(), (byte) 0x01, true);
        if (encoding.getData().available() > 0)
            pname = ullink.security.krb5.PrincipalName.parse(encoding.getData(), (byte) 0x02, true);
        if (encoding.getData().available() > 0)
            flags = ullink.security.krb5.internal.TicketFlags.parse(encoding.getData(), (byte) 0x03, true);
        if (encoding.getData().available() > 0)
            authtime = ullink.security.krb5.internal.KerberosTime.parse(encoding.getData(), (byte) 0x04, true);
        if (encoding.getData().available() > 0)
            starttime = ullink.security.krb5.internal.KerberosTime.parse(encoding.getData(), (byte) 0x05, true);
        if (encoding.getData().available() > 0)
            endtime = ullink.security.krb5.internal.KerberosTime.parse(encoding.getData(), (byte) 0x06, true);
        if (encoding.getData().available() > 0)
            renewTill = ullink.security.krb5.internal.KerberosTime.parse(encoding.getData(), (byte) 0x07, true);
        if (encoding.getData().available() > 0)
            srealm = ullink.security.krb5.Realm.parse(encoding.getData(), (byte) 0x08, true);
        if (encoding.getData().available() > 0)
            sname = ullink.security.krb5.PrincipalName.parse(encoding.getData(), (byte) 0x09, true);
        if (encoding.getData().available() > 0)
            caddr = ullink.security.krb5.internal.HostAddresses.parse(encoding.getData(), (byte) 0x0A, true);
        if (encoding.getData().available() > 0)
            throw new ullink.security.krb5.Asn1Exception(Krb5.ASN1_BAD_ID);
    }

    /**
     * Encodes an KrbCredInfo object.
     * @return the byte array of encoded KrbCredInfo object.
     * @exception ullink.security.krb5.Asn1Exception if an error occurs while decoding an ASN1 encoded data.
     * @exception IOException if an I/O error occurs while reading encoded data.
     */
    public byte[] asn1Encode() throws ullink.security.krb5.Asn1Exception, IOException {
        Vector<DerValue> v = new Vector<DerValue> ();
        v.addElement(new DerValue(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x00), key.asn1Encode()));
        if (prealm != null)
        v.addElement(new DerValue(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x01), prealm.asn1Encode()));
        if (pname != null)
        v.addElement(new DerValue(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x02), pname.asn1Encode()));
        if (flags != null)
        v.addElement(new DerValue(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x03), flags.asn1Encode()));
        if (authtime != null)
        v.addElement(new DerValue(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x04), authtime.asn1Encode()));
        if (starttime != null)
        v.addElement(new DerValue(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x05), starttime.asn1Encode()));
        if (endtime != null)
        v.addElement(new DerValue(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x06), endtime.asn1Encode()));
        if (renewTill != null)
        v.addElement(new DerValue(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x07), renewTill.asn1Encode()));
        if (srealm != null)
        v.addElement(new DerValue(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x08), srealm.asn1Encode()));
        if (sname != null)
        v.addElement(new DerValue(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x09), sname.asn1Encode()));
        if (caddr != null)
        v.addElement(new DerValue(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x0A), caddr.asn1Encode()));
        DerValue der[] = new DerValue[v.size()];
        v.copyInto(der);
        DerOutputStream out = new DerOutputStream();
        out.putSequence(der);
        return out.toByteArray();
    }

    public Object clone() {
        KrbCredInfo kcred = new KrbCredInfo();
        kcred.key = (ullink.security.krb5.EncryptionKey)key.clone();
        // optional fields
        if (prealm != null)
            kcred.prealm = (ullink.security.krb5.Realm)prealm.clone();
        if (pname != null)
            kcred.pname = (ullink.security.krb5.PrincipalName)pname.clone();
        if (flags != null)
            kcred.flags = (ullink.security.krb5.internal.TicketFlags)flags.clone();
        if (authtime != null)
            kcred.authtime = (ullink.security.krb5.internal.KerberosTime)authtime.clone();
        if (starttime != null)
            kcred.starttime = (ullink.security.krb5.internal.KerberosTime)starttime.clone();
        if (endtime != null)
            kcred.endtime = (ullink.security.krb5.internal.KerberosTime)endtime.clone();
        if (renewTill != null)
            kcred.renewTill = (ullink.security.krb5.internal.KerberosTime)renewTill.clone();
        if (srealm != null)
            kcred.srealm = (ullink.security.krb5.Realm)srealm.clone();
        if (sname != null)
            kcred.sname = (ullink.security.krb5.PrincipalName)sname.clone();
        if (caddr != null)
            kcred.caddr = (ullink.security.krb5.internal.HostAddresses)caddr.clone();
        return kcred;
    }

}
