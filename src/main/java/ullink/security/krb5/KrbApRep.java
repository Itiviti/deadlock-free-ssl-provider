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

/**
 * This class encapsulates a KRB-AP-REP sent from the service to the
 * client.
 */
public class KrbApRep {
    private byte[] obuf;
    private byte[] ibuf;
    private ullink.security.krb5.internal.EncAPRepPart encPart; // although in plain text
    private ullink.security.krb5.internal.APRep apRepMessg;

    /**
     * Constructs a KRB-AP-REP to send to a client.
     * @throws ullink.security.krb5.KrbException
     * @throws IOException
     */
     // Used in AcceptSecContextToken
    public KrbApRep(ullink.security.krb5.KrbApReq incomingReq,
                    boolean useSeqNumber,
        boolean useSubKey) throws ullink.security.krb5.KrbException, IOException {

        ullink.security.krb5.EncryptionKey subKey =
            (useSubKey?
             new ullink.security.krb5.EncryptionKey(incomingReq.getCreds().getSessionKey()):null);
        ullink.security.krb5.internal.SeqNumber seqNum = new ullink.security.krb5.internal.LocalSeqNumber();

        init(incomingReq, subKey, seqNum);
    }

    /**
     * Constructs a KRB-AP-REQ from the bytes received from a service.
     * @throws ullink.security.krb5.KrbException
     * @throws IOException
     */
     // Used in AcceptSecContextToken
    public KrbApRep(byte[] message, Credentials tgtCreds,
                    ullink.security.krb5.KrbApReq outgoingReq) throws ullink.security.krb5.KrbException, IOException {
        this(message, tgtCreds);
        authenticate(outgoingReq);
    }

    private void init(ullink.security.krb5.KrbApReq apReq,
              ullink.security.krb5.EncryptionKey subKey,
        ullink.security.krb5.internal.SeqNumber seqNumber)
        throws ullink.security.krb5.KrbException, IOException {
        createMessage(
                      apReq.getCreds().key,
                      apReq.getCtime(),
                      apReq.cusec(),
                      subKey,
                      seqNumber);
        obuf = apRepMessg.asn1Encode();
    }


    /**
     * Constructs a KrbApRep object.
     * @param msg a byte array of reply message.
     * @param tgs_creds client's credential.
     * @exception ullink.security.krb5.KrbException
     * @exception IOException
     */
    private KrbApRep(byte[] msg, Credentials tgs_creds)
        throws ullink.security.krb5.KrbException, IOException {
        this(new DerValue(msg), tgs_creds);
    }

    /**
     * Constructs a KrbApRep object.
     * @param msg a byte array of reply message.
     * @param tgs_creds client's credential.
     * @exception ullink.security.krb5.KrbException
     * @exception IOException
     */
    private KrbApRep(DerValue encoding, Credentials tgs_creds)
        throws ullink.security.krb5.KrbException, IOException {
        ullink.security.krb5.internal.APRep rep = null;
        try {
            rep = new ullink.security.krb5.internal.APRep(encoding);
        } catch (ullink.security.krb5.Asn1Exception e) {
            rep = null;
            ullink.security.krb5.internal.KRBError err = new ullink.security.krb5.internal.KRBError(encoding);
            String errStr = err.getErrorString();
            String eText;
            if (errStr.charAt(errStr.length() - 1) == 0)
                eText = errStr.substring(0, errStr.length() - 1);
            else
                eText = errStr;
            ullink.security.krb5.KrbException ke = new ullink.security.krb5.KrbException(err.getErrorCode(), eText);
            ke.initCause(e);
            throw ke;
        }

        byte[] temp = rep.encPart.decrypt(tgs_creds.key,
            KeyUsage.KU_ENC_AP_REP_PART);
        byte[] enc_ap_rep_part = rep.encPart.reset(temp, true);

        encoding = new DerValue(enc_ap_rep_part);
        encPart = new ullink.security.krb5.internal.EncAPRepPart(encoding);
    }

    private void authenticate(ullink.security.krb5.KrbApReq apReq)
        throws ullink.security.krb5.KrbException, IOException {
        if (encPart.ctime.getSeconds() != apReq.getCtime().getSeconds() ||
            encPart.cusec != apReq.getCtime().getMicroSeconds())
            throw new ullink.security.krb5.internal.KrbApErrException(ullink.security.krb5.internal.Krb5.KRB_AP_ERR_MUT_FAIL);
    }


    /**
     * Returns the optional subkey stored in
     * this message. Returns null if none is stored.
     */
    public ullink.security.krb5.EncryptionKey getSubKey() {
        // XXX Can encPart be null
        return encPart.getSubKey();

    }

    /**
     * Returns the optional sequence number stored in the
     * this message. Returns null if none is stored.
     */
    public Integer getSeqNumber() {
        // XXX Can encPart be null
        return encPart.getSeqNumber();
    }

    /**
     * Returns the ASN.1 encoding that should be sent to the peer.
     */
    public byte[] getMessage() {
        return obuf;
    }

    private void createMessage(
                               ullink.security.krb5.EncryptionKey key,
                               ullink.security.krb5.internal.KerberosTime ctime,
                               int cusec,
                               ullink.security.krb5.EncryptionKey subKey,
                               ullink.security.krb5.internal.SeqNumber seqNumber)
        throws ullink.security.krb5.Asn1Exception, IOException,
            ullink.security.krb5.internal.KdcErrException, ullink.security.krb5.KrbCryptoException {

        Integer seqno = null;

        if (seqNumber != null)
            seqno = new Integer(seqNumber.current());

        encPart = new ullink.security.krb5.internal.EncAPRepPart(ctime,
                                   cusec,
                                   subKey,
                                   seqno);

        byte[] encPartEncoding = encPart.asn1Encode();

        ullink.security.krb5.EncryptedData encEncPart = new ullink.security.krb5.EncryptedData(key, encPartEncoding,
            KeyUsage.KU_ENC_AP_REP_PART);

        apRepMessg = new ullink.security.krb5.internal.APRep(encEncPart);
    }

}
