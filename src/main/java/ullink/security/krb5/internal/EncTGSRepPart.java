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

import ullink.security.util.DerValue;

import java.io.IOException;

public class EncTGSRepPart extends EncKDCRepPart {

        public EncTGSRepPart(
                ullink.security.krb5.EncryptionKey new_key,
                ullink.security.krb5.internal.LastReq new_lastReq,
                int new_nonce,
                ullink.security.krb5.internal.KerberosTime new_keyExpiration,
                ullink.security.krb5.internal.TicketFlags new_flags,
                ullink.security.krb5.internal.KerberosTime new_authtime,
                ullink.security.krb5.internal.KerberosTime new_starttime,
                ullink.security.krb5.internal.KerberosTime new_endtime,
                ullink.security.krb5.internal.KerberosTime new_renewTill,
                ullink.security.krb5.Realm new_srealm,
                ullink.security.krb5.PrincipalName new_sname,
                ullink.security.krb5.internal.HostAddresses new_caddr
        ) {
                super(
                        new_key,
                        new_lastReq,
                        new_nonce,
                        new_keyExpiration,
                        new_flags,
                        new_authtime,
                        new_starttime,
                        new_endtime,
                        new_renewTill,
                        new_srealm,
                        new_sname,
                        new_caddr,
                        ullink.security.krb5.internal.Krb5.KRB_ENC_TGS_REP_PART
                );
        }

        public EncTGSRepPart(byte[] data) throws ullink.security.krb5.Asn1Exception,
                IOException, ullink.security.krb5.KrbException {
                init(new DerValue(data));
        }

        public EncTGSRepPart(DerValue encoding) throws ullink.security.krb5.Asn1Exception,
                IOException, ullink.security.krb5.KrbException {
                init(encoding);
        }

        private void init(DerValue encoding) throws ullink.security.krb5.Asn1Exception,
                IOException, ullink.security.krb5.KrbException {
                init(encoding, ullink.security.krb5.internal.Krb5.KRB_ENC_TGS_REP_PART);
        }

        public byte[] asn1Encode() throws ullink.security.krb5.Asn1Exception,
                IOException {
                return asn1Encode(ullink.security.krb5.internal.Krb5.KRB_ENC_TGS_REP_PART);
        }

}
