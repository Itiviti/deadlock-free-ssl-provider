/*
 * Copyright (c) 2000, 2004, Oracle and/or its affiliates. All rights reserved.
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

package ullink.security.krb5;

import ullink.security.krb5.internal.crypto.KeyUsage;

import java.io.IOException;

class KrbSafe extends KrbAppMessage {

    private byte[] obuf;
    private byte[] userData;

    public KrbSafe(byte[] userData,
                   ullink.security.krb5.Credentials creds,
                   ullink.security.krb5.EncryptionKey subKey,
                   ullink.security.krb5.internal.KerberosTime timestamp,
                   ullink.security.krb5.internal.SeqNumber seqNumber,
                   ullink.security.krb5.internal.HostAddress saddr,
                   ullink.security.krb5.internal.HostAddress raddr
                   )  throws ullink.security.krb5.KrbException, IOException {
        ullink.security.krb5.EncryptionKey reqKey = null;
        if (subKey != null)
            reqKey = subKey;
        else
            reqKey = creds.key;

        obuf = mk_safe(userData,
                       reqKey,
                       timestamp,
                       seqNumber,
                       saddr,
                       raddr
                       );
    }

    public KrbSafe(byte[] msg,
                   ullink.security.krb5.Credentials creds,
                   ullink.security.krb5.EncryptionKey subKey,
                   ullink.security.krb5.internal.SeqNumber seqNumber,
                   ullink.security.krb5.internal.HostAddress saddr,
                   ullink.security.krb5.internal.HostAddress raddr,
                   boolean timestampRequired,
                   boolean seqNumberRequired
                   )  throws ullink.security.krb5.KrbException, IOException {

        ullink.security.krb5.internal.KRBSafe krb_safe = new ullink.security.krb5.internal.KRBSafe(msg);

        ullink.security.krb5.EncryptionKey reqKey = null;
        if (subKey != null)
            reqKey = subKey;
        else
            reqKey = creds.key;

        userData = rd_safe(
                           krb_safe,
                           reqKey,
                           seqNumber,
                           saddr,
                           raddr,
                           timestampRequired,
                           seqNumberRequired,
                           creds.client,
                           creds.client.getRealm()
                           );
    }

    public byte[] getMessage() {
        return obuf;
    }

    public byte[] getData() {
        return userData;
    }

    private  byte[] mk_safe(byte[] userData,
                            ullink.security.krb5.EncryptionKey key,
                            ullink.security.krb5.internal.KerberosTime timestamp,
                            ullink.security.krb5.internal.SeqNumber seqNumber,
                            ullink.security.krb5.internal.HostAddress sAddress,
                            ullink.security.krb5.internal.HostAddress rAddress
                            ) throws ullink.security.krb5.Asn1Exception, IOException, ullink.security.krb5.internal.KdcErrException,
            ullink.security.krb5.internal.KrbApErrException, ullink.security.krb5.KrbCryptoException {

                                Integer usec = null;
                                Integer seqno = null;

                                if (timestamp != null)
                                usec = new Integer(timestamp.getMicroSeconds());

                                if (seqNumber != null) {
                                    seqno = new Integer(seqNumber.current());
                                    seqNumber.step();
                                }

                                ullink.security.krb5.internal.KRBSafeBody krb_safeBody =
                                new ullink.security.krb5.internal.KRBSafeBody(userData,
                                                timestamp,
                                                usec,
                                                seqno,
                                                sAddress,
                                                rAddress
                                                );

                                byte[] temp = krb_safeBody.asn1Encode();
                                ullink.security.krb5.Checksum cksum = new ullink.security.krb5.Checksum(
                                    ullink.security.krb5.Checksum.SAFECKSUMTYPE_DEFAULT,
                                    temp,
                                    key,
                                    KeyUsage.KU_KRB_SAFE_CKSUM
                                    );

                                ullink.security.krb5.internal.KRBSafe krb_safe = new ullink.security.krb5.internal.KRBSafe(krb_safeBody, cksum);

                                temp = krb_safe.asn1Encode();

                                return krb_safe.asn1Encode();
                            }

    private byte[] rd_safe(ullink.security.krb5.internal.KRBSafe krb_safe,
                           ullink.security.krb5.EncryptionKey key,
                           ullink.security.krb5.internal.SeqNumber seqNumber,
                           ullink.security.krb5.internal.HostAddress sAddress,
                           ullink.security.krb5.internal.HostAddress rAddress,
                           boolean timestampRequired,
                           boolean seqNumberRequired,
                           ullink.security.krb5.PrincipalName cname,
                           ullink.security.krb5.Realm crealm
                           ) throws ullink.security.krb5.Asn1Exception, ullink.security.krb5.internal.KdcErrException,
            ullink.security.krb5.internal.KrbApErrException, IOException, ullink.security.krb5.KrbCryptoException {

                               byte[] temp = krb_safe.safeBody.asn1Encode();

                               if (!krb_safe.cksum.verifyKeyedChecksum(temp, key,
                                   KeyUsage.KU_KRB_SAFE_CKSUM)) {
                                       throw new ullink.security.krb5.internal.KrbApErrException(
                                           ullink.security.krb5.internal.Krb5.KRB_AP_ERR_MODIFIED);
                               }

                               check(krb_safe.safeBody.timestamp,
                                     krb_safe.safeBody.usec,
                                     krb_safe.safeBody.seqNumber,
                                     krb_safe.safeBody.sAddress,
                                     krb_safe.safeBody.rAddress,
                                     seqNumber,
                                     sAddress,
                                     rAddress,
                                     timestampRequired,
                                     seqNumberRequired,
                                     cname,
                                     crealm
                                     );

                               return krb_safe.safeBody.userData;
                           }
}
