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
import java.math.BigInteger;
import java.util.Vector;

/**
 * Implements the ASN.1 KDC-REQ-BODY type.
 *
 * <xmp>
 * KDC-REQ-BODY ::= SEQUENCE {
 *      kdc-options             [0] KDCOptions,
 *      cname                   [1] PrincipalName OPTIONAL
 *                                    -- Used only in AS-REQ --,
 *      realm                   [2] Realm
 *                                    -- Server's realm
 *                                    -- Also client's in AS-REQ --,
 *      sname                   [3] PrincipalName OPTIONAL,
 *      from                    [4] KerberosTime OPTIONAL,
 *      till                    [5] KerberosTime,
 *      rtime                   [6] KerberosTime OPTIONAL,
 *      nonce                   [7] UInt32,
 *      etype                   [8] SEQUENCE OF Int32 -- EncryptionType
 *                                    -- in preference order --,
 *      addresses               [9] HostAddresses OPTIONAL,
 *      enc-authorization-data  [10] EncryptedData OPTIONAL
 *                                    -- AuthorizationData --,
 *      additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
 *                                       -- NOTE: not empty
 * }
 * </xmp>
 *
 * <p>
 * This definition reflects the Network Working Group RFC 4120
 * specification available at
 * <a href="http://www.ietf.org/rfc/rfc4120.txt">
 * http://www.ietf.org/rfc/rfc4120.txt</a>.
 */

public class KDCReqBody {
    public KDCOptions kdcOptions;
    public ullink.security.krb5.PrincipalName cname; //optional in ASReq only
    public ullink.security.krb5.Realm crealm;
    public ullink.security.krb5.PrincipalName sname; //optional
    public ullink.security.krb5.internal.KerberosTime from; //optional
    public ullink.security.krb5.internal.KerberosTime till;
    public ullink.security.krb5.internal.KerberosTime rtime; //optional
    public ullink.security.krb5.internal.HostAddresses addresses; //optional

    private int nonce;
    private int[] eType = null; //a sequence; not optional
    private ullink.security.krb5.EncryptedData encAuthorizationData; //optional
    private ullink.security.krb5.internal.Ticket[] additionalTickets; //optional

    public KDCReqBody(
            KDCOptions new_kdcOptions,
            ullink.security.krb5.PrincipalName new_cname, //optional in ASReq only
            ullink.security.krb5.Realm new_crealm,
            ullink.security.krb5.PrincipalName new_sname, //optional
            ullink.security.krb5.internal.KerberosTime new_from, //optional
            ullink.security.krb5.internal.KerberosTime new_till,
            ullink.security.krb5.internal.KerberosTime new_rtime, //optional
            int new_nonce,
            int[] new_eType, //a sequence; not optional
            ullink.security.krb5.internal.HostAddresses new_addresses, //optional
            ullink.security.krb5.EncryptedData new_encAuthorizationData, //optional
            ullink.security.krb5.internal.Ticket[] new_additionalTickets //optional
            ) throws IOException {
        kdcOptions = new_kdcOptions;
        cname = new_cname;
        crealm = new_crealm;
        sname = new_sname;
        from = new_from;
        till = new_till;
        rtime = new_rtime;
        nonce = new_nonce;
        if (new_eType != null) {
            eType = new_eType.clone();
        }
        addresses = new_addresses;
        encAuthorizationData = new_encAuthorizationData;
        if (new_additionalTickets != null) {
            additionalTickets = new ullink.security.krb5.internal.Ticket[new_additionalTickets.length];
            for (int i = 0; i < new_additionalTickets.length; i++) {
                if (new_additionalTickets[i] == null) {
                    throw new IOException("Cannot create a KDCReqBody");
                } else {
                    additionalTickets[i] = (ullink.security.krb5.internal.Ticket)new_additionalTickets[i].clone();
                }
            }
        }
    }

    /**
     * Constructs a KDCReqBody object.
     * @param encoding a DER-encoded data.
     * @param msgType an int indicating whether it's KRB_AS_REQ or KRB_TGS_REQ type.
     * @exception ullink.security.krb5.Asn1Exception if an error occurs while decoding an ASN1 encoded data.
     * @exception IOException if an I/O error occurs while reading encoded data.
     * @exception ullink.security.krb5.RealmException if an error occurs while constructing a Realm object from the encoded data.
     *
     */
    public KDCReqBody(DerValue encoding, int msgType)
            throws ullink.security.krb5.Asn1Exception, ullink.security.krb5.RealmException, ullink.security.krb5.KrbException, IOException {
        DerValue der, subDer;
        addresses = null;
        encAuthorizationData = null;
        additionalTickets = null;
        if (encoding.getTag() != DerValue.tag_Sequence) {
            throw new ullink.security.krb5.Asn1Exception(ullink.security.krb5.internal.Krb5.ASN1_BAD_ID);
        }
        kdcOptions = KDCOptions.parse(encoding.getData(), (byte) 0x00, false);
        cname = ullink.security.krb5.PrincipalName.parse(encoding.getData(), (byte) 0x01, true);
        if ((msgType != ullink.security.krb5.internal.Krb5.KRB_AS_REQ) && (cname != null)) {
            throw new ullink.security.krb5.Asn1Exception(ullink.security.krb5.internal.Krb5.ASN1_BAD_ID);
        }
        crealm = ullink.security.krb5.Realm.parse(encoding.getData(), (byte) 0x02, false);
        sname = ullink.security.krb5.PrincipalName.parse(encoding.getData(), (byte) 0x03, true);
        from = ullink.security.krb5.internal.KerberosTime.parse(encoding.getData(), (byte) 0x04, true);
        till = ullink.security.krb5.internal.KerberosTime.parse(encoding.getData(), (byte) 0x05, false);
        rtime = ullink.security.krb5.internal.KerberosTime.parse(encoding.getData(), (byte) 0x06, true);
        der = encoding.getData().getDerValue();
        if ((der.getTag() & (byte)0x1F) == (byte)0x07) {
            nonce = der.getData().getBigInteger().intValue();
        } else {
            throw new ullink.security.krb5.Asn1Exception(ullink.security.krb5.internal.Krb5.ASN1_BAD_ID);
        }
        der = encoding.getData().getDerValue();
        Vector<Integer> v = new Vector<Integer> ();
        if ((der.getTag() & (byte)0x1F) == (byte)0x08) {
            subDer = der.getData().getDerValue();

            if (subDer.getTag() == DerValue.tag_SequenceOf) {
                while(subDer.getData().available() > 0) {
                    v.addElement(subDer.getData().getBigInteger().intValue());
                }
                eType = new int[v.size()];
                for (int i = 0; i < v.size(); i++) {
                    eType[i] = v.elementAt(i);
                }
            } else {
                throw new ullink.security.krb5.Asn1Exception(ullink.security.krb5.internal.Krb5.ASN1_BAD_ID);
            }
        } else {
            throw new ullink.security.krb5.Asn1Exception(ullink.security.krb5.internal.Krb5.ASN1_BAD_ID);
        }
        if (encoding.getData().available() > 0) {
            addresses = ullink.security.krb5.internal.HostAddresses.parse(encoding.getData(), (byte) 0x09, true);
        }
        if (encoding.getData().available() > 0) {
            encAuthorizationData = ullink.security.krb5.EncryptedData.parse(encoding.getData(), (byte) 0x0A, true);
        }
        if (encoding.getData().available() > 0) {
            Vector<ullink.security.krb5.internal.Ticket> tempTickets = new Vector<ullink.security.krb5.internal.Ticket> ();
            der = encoding.getData().getDerValue();
            if ((der.getTag() & (byte)0x1F) == (byte)0x0B) {
                subDer = der.getData().getDerValue();
                if (subDer.getTag() == DerValue.tag_SequenceOf) {
                    while (subDer.getData().available() > 0) {
                        tempTickets.addElement(new ullink.security.krb5.internal.Ticket(subDer.getData().getDerValue()));
                    }
                } else {
                    throw new ullink.security.krb5.Asn1Exception(ullink.security.krb5.internal.Krb5.ASN1_BAD_ID);
                }
                if (tempTickets.size() > 0) {
                    additionalTickets = new ullink.security.krb5.internal.Ticket[tempTickets.size()];
                    tempTickets.copyInto(additionalTickets);
                }
            } else {
                throw new ullink.security.krb5.Asn1Exception(ullink.security.krb5.internal.Krb5.ASN1_BAD_ID);
            }
        }
        if (encoding.getData().available() > 0) {
            throw new ullink.security.krb5.Asn1Exception(ullink.security.krb5.internal.Krb5.ASN1_BAD_ID);
        }
    }

    /**
     * Encodes this object to an OutputStream.
     *
     * @return an byte array of encoded data.
     * @exception ullink.security.krb5.Asn1Exception if an error occurs while decoding an ASN1 encoded data.
     * @exception IOException if an I/O error occurs while reading encoded data.
     *
     */
    public byte[] asn1Encode(int msgType) throws ullink.security.krb5.Asn1Exception, IOException {
        Vector<DerValue> v = new Vector<DerValue> ();
        v.addElement(new DerValue(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x00), kdcOptions.asn1Encode()));
        if (msgType == ullink.security.krb5.internal.Krb5.KRB_AS_REQ) {
            if (cname != null) {
                v.addElement(new DerValue(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x01), cname.asn1Encode()));
            }
        }
        v.addElement(new DerValue(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x02), crealm.asn1Encode()));
        if (sname != null) {
            v.addElement(new DerValue(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x03), sname.asn1Encode()));
        }
        if (from != null) {
            v.addElement(new DerValue(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x04), from.asn1Encode()));
        }
        v.addElement(new DerValue(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x05), till.asn1Encode()));
        if (rtime != null) {
            v.addElement(new DerValue(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x06), rtime.asn1Encode()));
        }
        DerOutputStream temp = new DerOutputStream();
        temp.putInteger(BigInteger.valueOf(nonce));
        v.addElement(new DerValue(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x07), temp.toByteArray()));
        //revisit, if empty eType sequences are allowed
        temp = new DerOutputStream();
        for (int i = 0; i < eType.length; i++) {
            temp.putInteger(BigInteger.valueOf(eType[i]));
        }
        DerOutputStream eTypetemp = new DerOutputStream();
        eTypetemp.write(DerValue.tag_SequenceOf, temp);
        v.addElement(new DerValue(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x08), eTypetemp.toByteArray()));
        if (addresses != null) {
            v.addElement(new DerValue(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x09), addresses.asn1Encode()));
        }
        if (encAuthorizationData != null) {
            v.addElement(new DerValue(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x0A), encAuthorizationData.asn1Encode()));
        }
        if (additionalTickets != null && additionalTickets.length > 0) {
            temp = new DerOutputStream();
            for (int i = 0; i < additionalTickets.length; i++) {
                temp.write(additionalTickets[i].asn1Encode());
            }
            DerOutputStream ticketsTemp = new DerOutputStream();
            ticketsTemp.write(DerValue.tag_SequenceOf, temp);
            v.addElement(new DerValue(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x0B), ticketsTemp.toByteArray()));
        }
        DerValue der[] = new DerValue[v.size()];
        v.copyInto(der);
        temp = new DerOutputStream();
        temp.putSequence(der);
        return temp.toByteArray();
    }

    public int getNonce() {
        return nonce;
    }
}
