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
/**
 * Implements the ASN.1 KDC-REP type.
 *
 * <xmp>
 * KDC-REP         ::= SEQUENCE {
 *         pvno            [0] INTEGER (5),
 *         msg-type        [1] INTEGER (11 -- AS -- | 13 -- TGS --),
 *         padata          [2] SEQUENCE OF PA-DATA OPTIONAL
 *                                   -- NOTE: not empty --,
 *         crealm          [3] Realm,
 *         cname           [4] PrincipalName,
 *         ticket          [5] Ticket,
 *         enc-part        [6] EncryptedData
 *                                   -- EncASRepPart or EncTGSRepPart,
 *                                   -- as appropriate
 * }
 * </xmp>
 *
 * <p>
 * This definition reflects the Network Working Group RFC 4120
 * specification available at
 * <a href="http://www.ietf.org/rfc/rfc4120.txt">
 * http://www.ietf.org/rfc/rfc4120.txt</a>.
 */

public class KDCRep {
        public ullink.security.krb5.Realm crealm;
        public ullink.security.krb5.PrincipalName cname;
        public ullink.security.krb5.internal.Ticket ticket;
        public ullink.security.krb5.EncryptedData encPart;
        public EncKDCRepPart encKDCRepPart; //not part of ASN.1 encoding

        private int pvno;
        private int msgType;
        private ullink.security.krb5.internal.PAData[] pAData = null; //optional
        private boolean DEBUG = ullink.security.krb5.internal.Krb5.DEBUG;

        public KDCRep(
                ullink.security.krb5.internal.PAData[] new_pAData,
                ullink.security.krb5.Realm new_crealm,
                ullink.security.krb5.PrincipalName new_cname,
                ullink.security.krb5.internal.Ticket new_ticket,
                ullink.security.krb5.EncryptedData new_encPart,
                int req_type
        ) throws IOException {
                pvno = ullink.security.krb5.internal.Krb5.PVNO;
                msgType = req_type;
                if (new_pAData != null) {
                    pAData = new ullink.security.krb5.internal.PAData[new_pAData.length];
                    for (int i = 0; i < new_pAData.length; i++) {
                        if (new_pAData[i] == null) {
                            throw new IOException("Cannot create a KDCRep");
                        } else {
                            pAData[i] = (ullink.security.krb5.internal.PAData)new_pAData[i].clone();
                        }
                    }
                }
                crealm = new_crealm;
                cname = new_cname;
                ticket = new_ticket;
                encPart = new_encPart;
        }

        public KDCRep() {
        }

        public KDCRep(byte[] data, int req_type) throws ullink.security.krb5.Asn1Exception, ullink.security.krb5.internal.KrbApErrException, ullink.security.krb5.RealmException, IOException {
                init(new DerValue(data), req_type);
        }

        public KDCRep(DerValue encoding, int req_type) throws ullink.security.krb5.Asn1Exception,
                ullink.security.krb5.RealmException, ullink.security.krb5.internal.KrbApErrException, IOException {
                init(encoding, req_type);
        }

    /*
    // Not used? Don't know what keyusage to use here %%%

        public void decrypt(EncryptionKey key) throws Asn1Exception,
                IOException, KrbException, RealmException {
                encKDCRepPart = new EncKDCRepPart(encPart.decrypt(key),
                        msgType);
        }
*/

        /**
         * Initializes an KDCRep object.
         *
         * @param encoding a single DER-encoded value.
         * @param req_type reply message type.
         * @exception ullink.security.krb5.Asn1Exception if an error occurs while decoding an ASN1 encoded data.
         * @exception IOException if an I/O error occurs while reading encoded data.
         * @exception ullink.security.krb5.RealmException if an error occurs while constructing a Realm object from DER-encoded data.
         * @exception ullink.security.krb5.internal.KrbApErrException if the value read from the DER-encoded data stream does not match the pre-defined value.
         *
         */
        protected void init(DerValue encoding, int req_type)
            throws ullink.security.krb5.Asn1Exception, ullink.security.krb5.RealmException, IOException,
                ullink.security.krb5.internal.KrbApErrException {
            DerValue der, subDer;
            if ((encoding.getTag() & 0x1F) != req_type) {
                if (DEBUG) {
                    System.out.println(">>> KDCRep: init() " +
                                       "encoding tag is " +
                                       encoding.getTag() +
                                       " req type is " + req_type);
                }
                throw new ullink.security.krb5.Asn1Exception(ullink.security.krb5.internal.Krb5.ASN1_BAD_ID);
            }
            der = encoding.getData().getDerValue();
            if (der.getTag() != DerValue.tag_Sequence) {
                throw new ullink.security.krb5.Asn1Exception(ullink.security.krb5.internal.Krb5.ASN1_BAD_ID);
            }
            subDer = der.getData().getDerValue();
            if ((subDer.getTag() & 0x1F) == 0x00) {
                pvno = subDer.getData().getBigInteger().intValue();
                if (pvno != ullink.security.krb5.internal.Krb5.PVNO)
                    throw new ullink.security.krb5.internal.KrbApErrException(ullink.security.krb5.internal.Krb5.KRB_AP_ERR_BADVERSION);
            } else {
                throw new ullink.security.krb5.Asn1Exception(ullink.security.krb5.internal.Krb5.ASN1_BAD_ID);
            }
            subDer = der.getData().getDerValue();
            if ((subDer.getTag() & 0x1F) == 0x01) {
                msgType = subDer.getData().getBigInteger().intValue();
                if (msgType != req_type) {
                    throw new ullink.security.krb5.internal.KrbApErrException(ullink.security.krb5.internal.Krb5.KRB_AP_ERR_MSG_TYPE);
                }
            } else {
                throw new ullink.security.krb5.Asn1Exception(ullink.security.krb5.internal.Krb5.ASN1_BAD_ID);
            }
            if ((der.getData().peekByte() & 0x1F) == 0x02) {
                subDer = der.getData().getDerValue();
                DerValue[] padata = subDer.getData().getSequence(1);
                pAData = new ullink.security.krb5.internal.PAData[padata.length];
                for (int i = 0; i < padata.length; i++) {
                    pAData[i] = new ullink.security.krb5.internal.PAData(padata[i]);
                }
            } else {
                pAData = null;
            }
            crealm = ullink.security.krb5.Realm.parse(der.getData(), (byte) 0x03, false);
            cname = ullink.security.krb5.PrincipalName.parse(der.getData(), (byte) 0x04, false);
            ticket = ullink.security.krb5.internal.Ticket.parse(der.getData(), (byte) 0x05, false);
            encPart = ullink.security.krb5.EncryptedData.parse(der.getData(), (byte) 0x06, false);
            if (der.getData().available() > 0) {
                throw new ullink.security.krb5.Asn1Exception(ullink.security.krb5.internal.Krb5.ASN1_BAD_ID);
            }
        }


        /**
         * Encodes this object to a byte array.
         * @return byte array of encoded APReq object.
         * @exception ullink.security.krb5.Asn1Exception if an error occurs while decoding an ASN1 encoded data.
         * @exception IOException if an I/O error occurs while reading encoded data.
         *
         */
        public byte[] asn1Encode() throws ullink.security.krb5.Asn1Exception, IOException {

            DerOutputStream bytes = new DerOutputStream();
            DerOutputStream temp = new DerOutputStream();
            temp.putInteger(BigInteger.valueOf(pvno));
            bytes.write(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x00), temp);
            temp = new DerOutputStream();
            temp.putInteger(BigInteger.valueOf(msgType));
            bytes.write(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x01), temp);
            if (pAData != null && pAData.length > 0) {
                DerOutputStream padata_stream = new DerOutputStream();
                for (int i = 0; i < pAData.length; i++) {
                    padata_stream.write(pAData[i].asn1Encode());
                }
                temp = new DerOutputStream();
                temp.write(DerValue.tag_SequenceOf, padata_stream);
                bytes.write(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x02), temp);
            }
            bytes.write(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x03), crealm.asn1Encode());
            bytes.write(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x04), cname.asn1Encode());
            bytes.write(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x05), ticket.asn1Encode());
            bytes.write(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte)0x06), encPart.asn1Encode());
            temp = new DerOutputStream();
            temp.write(DerValue.tag_Sequence, bytes);
            return temp.toByteArray();
        }
}
