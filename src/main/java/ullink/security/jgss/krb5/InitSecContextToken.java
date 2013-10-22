/*
 * Copyright (c) 2000, 2007, Oracle and/or its affiliates. All rights reserved.
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

package ullink.security.jgss.krb5;

import org.ietf.jgss.GSSException;
import ullink.security.util.DerValue;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;

class InitSecContextToken extends InitialToken {

    private ullink.security.krb5.KrbApReq apReq = null;

    /**
     * For the context initiator to call. It constructs a new
     * InitSecContextToken to send over to the peer containing the desired
     * flags and the AP-REQ. It also updates the context with the local
     * sequence number and shared context key.
     * (When mutual auth is enabled the peer has an opportunity to
     * renegotiate the session key in the followup AcceptSecContextToken
     * that it sends.)
     */
    InitSecContextToken(ullink.security.jgss.krb5.Krb5Context context,
                               ullink.security.krb5.Credentials tgt,
                               ullink.security.krb5.Credentials serviceTicket)
        throws ullink.security.krb5.KrbException, IOException, GSSException {

        boolean mutualRequired = context.getMutualAuthState();
        boolean useSubkey = true; // MIT Impl will crash if this is not set!
        boolean useSequenceNumber = true;

        OverloadedChecksum gssChecksum =
            new OverloadedChecksum(context, tgt, serviceTicket);

        ullink.security.krb5.Checksum checksum = gssChecksum.getChecksum();

        apReq = new ullink.security.krb5.KrbApReq(serviceTicket,
                             mutualRequired,
                             useSubkey,
                             useSequenceNumber,
                             checksum);

        context.resetMySequenceNumber(apReq.getSeqNumber().intValue());

        ullink.security.krb5.EncryptionKey subKey = apReq.getSubKey();
        if (subKey != null)
            context.setKey(subKey);
        else
            context.setKey(serviceTicket.getSessionKey());

        if (!mutualRequired)
            context.resetPeerSequenceNumber(0);
    }

    /**
     * For the context acceptor to call. It reads the bytes out of an
     * InputStream and constructs an InitSecContextToken with them.
     */
    InitSecContextToken(ullink.security.jgss.krb5.Krb5Context context, ullink.security.krb5.EncryptionKey[] keys,
                               InputStream is)
        throws IOException, GSSException, ullink.security.krb5.KrbException {

        int tokenId = ((is.read()<<8) | is.read());

        if (tokenId != ullink.security.jgss.krb5.Krb5Token.AP_REQ_ID)
            throw new GSSException(GSSException.DEFECTIVE_TOKEN, -1,
                                   "AP_REQ token id does not match!");

        // XXX Modify KrbApReq cons to take an InputStream
        byte[] apReqBytes =
            new DerValue(is).toByteArray();
        //debug("=====ApReqBytes: [" + getHexBytes(apReqBytes) + "]\n");

        InetAddress addr = null;
        if (context.getChannelBinding() != null) {
            addr = context.getChannelBinding().getInitiatorAddress();
        }
        apReq = new ullink.security.krb5.KrbApReq(apReqBytes, keys, addr);
        //debug("\nReceived AP-REQ and authenticated it.\n");

        ullink.security.krb5.EncryptionKey sessionKey
            = (ullink.security.krb5.EncryptionKey) apReq.getCreds().getSessionKey();

        /*
          System.out.println("\n\nSession key from service ticket is: " +
          getHexBytes(sessionKey.getBytes()));
        */

        ullink.security.krb5.EncryptionKey subKey = apReq.getSubKey();
        if (subKey != null) {
            context.setKey(subKey);
            /*
              System.out.println("Sub-Session key from authenticator is: " +
              getHexBytes(subKey.getBytes()) + "\n");
            */
        } else {
            context.setKey(sessionKey);
            //System.out.println("Sub-Session Key Missing in Authenticator.\n");
        }

        OverloadedChecksum gssChecksum =
            new OverloadedChecksum(context, apReq.getChecksum(), sessionKey);
        gssChecksum.setContextFlags(context);
        ullink.security.krb5.Credentials delegCred = gssChecksum.getDelegatedCreds();
        if (delegCred != null) {
            ullink.security.jgss.krb5.Krb5CredElement credElement =
                ullink.security.jgss.krb5.Krb5InitCredential.getInstance(
                        (ullink.security.jgss.krb5.Krb5NameElement) context.getSrcName(),
                        delegCred);
            context.setDelegCred(credElement);
        }

        Integer apReqSeqNumber = apReq.getSeqNumber();
        int peerSeqNumber = (apReqSeqNumber != null ?
                             apReqSeqNumber.intValue() :
                             0);
        context.resetPeerSequenceNumber(peerSeqNumber);
        if (!context.getMutualAuthState())
            // Use the same sequence number as the peer
            // (Behaviour exhibited by the Windows SSPI server)
            context.resetMySequenceNumber(peerSeqNumber);
    }

    public final ullink.security.krb5.KrbApReq getKrbApReq() {
        return apReq;
    }

    public final byte[] encode() throws IOException {
        byte[] apReqBytes = apReq.getMessage();
        byte[] retVal = new byte[2 + apReqBytes.length];
        writeInt(ullink.security.jgss.krb5.Krb5Token.AP_REQ_ID, retVal, 0);
        System.arraycopy(apReqBytes, 0, retVal, 2, apReqBytes.length);
        //      System.out.println("GSS-Token with AP_REQ is:");
        //      System.out.println(getHexBytes(retVal));
        return retVal;
    }
}
