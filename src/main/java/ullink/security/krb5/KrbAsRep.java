/*
 * Copyright (c) 2000, 2005, Oracle and/or its affiliates. All rights reserved.
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

import ullink.security.krb5.internal.crypto.EType;
import ullink.security.krb5.internal.crypto.KeyUsage;
import ullink.security.util.DerValue;

import java.io.IOException;

/**
 * This class encapsulates a AS-REP message that the KDC sends to the
 * client.
 */
public class KrbAsRep extends KrbKdcRep {

    private ullink.security.krb5.internal.ASRep rep;
    private ullink.security.krb5.Credentials creds;

    private boolean DEBUG = ullink.security.krb5.internal.Krb5.DEBUG;

    KrbAsRep(byte[] ibuf, ullink.security.krb5.EncryptionKey[] keys, ullink.security.krb5.KrbAsReq asReq) throws
            ullink.security.krb5.KrbException, ullink.security.krb5.Asn1Exception, IOException {
        if (keys == null)
            throw new ullink.security.krb5.KrbException(ullink.security.krb5.internal.Krb5.API_INVALID_ARG);
        DerValue encoding = new DerValue(ibuf);
        ullink.security.krb5.internal.ASReq req = asReq.getMessage();
        ullink.security.krb5.internal.ASRep rep = null;
        try {
            rep = new ullink.security.krb5.internal.ASRep(encoding);
        } catch (ullink.security.krb5.Asn1Exception e) {
            rep = null;
            ullink.security.krb5.internal.KRBError err = new ullink.security.krb5.internal.KRBError(encoding);
            String errStr = err.getErrorString();
            String eText = null; // pick up text sent by the server (if any)

            if (errStr != null && errStr.length() > 0) {
                if (errStr.charAt(errStr.length() - 1) == 0)
                    eText = errStr.substring(0, errStr.length() - 1);
                else
                    eText = errStr;
            }
            ullink.security.krb5.KrbException ke;
            if (eText == null) {
                // no text sent from server
                ke = new ullink.security.krb5.KrbException(err);
            } else {
                if (DEBUG) {
                    System.out.println("KRBError received: " + eText);
                }
                // override default text with server text
                ke = new ullink.security.krb5.KrbException(err, eText);
            }
            ke.initCause(e);
            throw ke;
        }

        int encPartKeyType = rep.encPart.getEType();
        ullink.security.krb5.EncryptionKey dkey = ullink.security.krb5.EncryptionKey.findKey(encPartKeyType, keys);

        if (dkey == null) {
            throw new ullink.security.krb5.KrbException(ullink.security.krb5.internal.Krb5.API_INVALID_ARG,
                "Cannot find key of appropriate type to decrypt AS REP - " +
                EType.toString(encPartKeyType));
        }

        byte[] enc_as_rep_bytes = rep.encPart.decrypt(dkey,
            KeyUsage.KU_ENC_AS_REP_PART);
        byte[] enc_as_rep_part = rep.encPart.reset(enc_as_rep_bytes, true);

        encoding = new DerValue(enc_as_rep_part);
        ullink.security.krb5.internal.EncASRepPart enc_part = new ullink.security.krb5.internal.EncASRepPart(encoding);
        rep.ticket.sname.setRealm(rep.ticket.realm);
        rep.encKDCRepPart = enc_part;

        check(req, rep);

        creds = new ullink.security.krb5.Credentials(
                                rep.ticket,
                                req.reqBody.cname,
                                rep.ticket.sname,
                                enc_part.key,
                                enc_part.flags,
                                enc_part.authtime,
                                enc_part.starttime,
                                enc_part.endtime,
                                enc_part.renewTill,
                                enc_part.caddr);
        if (DEBUG) {
            System.out.println(">>> KrbAsRep cons in KrbAsReq.getReply " +
                               req.reqBody.cname.getNameString());
        }

        this.rep = rep;
        this.creds = creds;
    }

    public ullink.security.krb5.Credentials getCreds() {
        return creds;
    }

    // made public for Kinit
    public ullink.security.krb5.internal.ccache.Credentials setCredentials() {
        return new ullink.security.krb5.internal.ccache.Credentials(rep);
    }
}
