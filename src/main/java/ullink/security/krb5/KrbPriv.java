/*
 * Copyright (c) 2000, 2006, Oracle and/or its affiliates. All rights reserved.
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
import ullink.security.util.DerValue;

import java.io.IOException;

/** XXX This class does not appear to be used. **/

class KrbPriv extends KrbAppMessage {
    private byte[] obuf;
    private byte[] userData;

    private KrbPriv(byte[] userData,
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

        obuf = mk_priv(
                       userData,
                       reqKey,
                       timestamp,
                       seqNumber,
                       saddr,
                       raddr
                       );
    }

    private KrbPriv(byte[] msg,
                   ullink.security.krb5.Credentials creds,
                   ullink.security.krb5.EncryptionKey subKey,
                   ullink.security.krb5.internal.SeqNumber seqNumber,
                   ullink.security.krb5.internal.HostAddress saddr,
                   ullink.security.krb5.internal.HostAddress raddr,
                   boolean timestampRequired,
                   boolean seqNumberRequired
                   )  throws ullink.security.krb5.KrbException, IOException {

        ullink.security.krb5.internal.KRBPriv krb_priv = new ullink.security.krb5.internal.KRBPriv(msg);
        ullink.security.krb5.EncryptionKey reqKey = null;
        if (subKey != null)
            reqKey = subKey;
        else
            reqKey = creds.key;
        userData = rd_priv(krb_priv,
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

    public byte[] getMessage() throws ullink.security.krb5.KrbException {
        return obuf;
    }

    public byte[] getData() {
        return userData;
    }

    private byte[] mk_priv(byte[] userData,
                           ullink.security.krb5.EncryptionKey key,
                           ullink.security.krb5.internal.KerberosTime timestamp,
                           ullink.security.krb5.internal.SeqNumber seqNumber,
                           ullink.security.krb5.internal.HostAddress sAddress,
                           ullink.security.krb5.internal.HostAddress rAddress
                           ) throws ullink.security.krb5.Asn1Exception, IOException,
            ullink.security.krb5.internal.KdcErrException, ullink.security.krb5.KrbCryptoException {

                               Integer usec = null;
                               Integer seqno = null;

                               if (timestamp != null)
                               usec = new Integer(timestamp.getMicroSeconds());

                               if (seqNumber != null) {
                                   seqno = new Integer(seqNumber.current());
                                   seqNumber.step();
                               }

                               ullink.security.krb5.internal.EncKrbPrivPart unenc_encKrbPrivPart =
                               new ullink.security.krb5.internal.EncKrbPrivPart(userData,
                                                  timestamp,
                                                  usec,
                                                  seqno,
                                                  sAddress,
                                                  rAddress
                                                  );

                               byte[] temp = unenc_encKrbPrivPart.asn1Encode();

                               ullink.security.krb5.EncryptedData encKrbPrivPart =
                               new ullink.security.krb5.EncryptedData(key, temp,
                                   KeyUsage.KU_ENC_KRB_PRIV_PART);

                               ullink.security.krb5.internal.KRBPriv krb_priv = new ullink.security.krb5.internal.KRBPriv(encKrbPrivPart);

                               temp = krb_priv.asn1Encode();

                               return krb_priv.asn1Encode();
                           }

    private byte[] rd_priv(ullink.security.krb5.internal.KRBPriv krb_priv,
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

                               byte[] bytes = krb_priv.encPart.decrypt(key,
                                   KeyUsage.KU_ENC_KRB_PRIV_PART);
                               byte[] temp = krb_priv.encPart.reset(bytes, true);
                               DerValue ref = new DerValue(temp);
                               ullink.security.krb5.internal.EncKrbPrivPart enc_part = new ullink.security.krb5.internal.EncKrbPrivPart(ref);

                               check(enc_part.timestamp,
                                     enc_part.usec,
                                     enc_part.seqNumber,
                                     enc_part.sAddress,
                                     enc_part.rAddress,
                                     seqNumber,
                                     sAddress,
                                     rAddress,
                                     timestampRequired,
                                     seqNumberRequired,
                                     cname,
                                     crealm
                                     );

                               return enc_part.userData;
                           }
}
