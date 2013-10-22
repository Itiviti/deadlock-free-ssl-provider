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
 * This class encapsulates the KRB-CRED message that a client uses to
 * send its delegated credentials to a server.
 *
 * Supports delegation of one ticket only.
 * @author Mayank Upadhyay
 */
public class KrbCred {

    private static boolean DEBUG = ullink.security.krb5.internal.Krb5.DEBUG;

    private byte[] obuf = null;
    private ullink.security.krb5.internal.KRBCred credMessg = null;
    private ullink.security.krb5.internal.Ticket ticket = null;
    private ullink.security.krb5.internal.EncKrbCredPart encPart = null;
    private ullink.security.krb5.Credentials creds = null;
    private ullink.security.krb5.internal.KerberosTime timeStamp = null;

         // Used in InitialToken with null key
    public KrbCred(ullink.security.krb5.Credentials tgt,
                   ullink.security.krb5.Credentials serviceTicket,
                   ullink.security.krb5.EncryptionKey key)
        throws ullink.security.krb5.KrbException, IOException {

        ullink.security.krb5.PrincipalName client = tgt.getClient();
        ullink.security.krb5.PrincipalName tgService = tgt.getServer();
        ullink.security.krb5.PrincipalName server = serviceTicket.getServer();
        if (!serviceTicket.getClient().equals(client))
            throw new ullink.security.krb5.KrbException(ullink.security.krb5.internal.Krb5.KRB_ERR_GENERIC,
                                "Client principal does not match");

        // XXX Check Windows flag OK-TO-FORWARD-TO

        // Invoke TGS-REQ to get a forwarded TGT for the peer

        ullink.security.krb5.internal.KDCOptions options = new ullink.security.krb5.internal.KDCOptions();
        options.set(ullink.security.krb5.internal.KDCOptions.FORWARDED, true);
        options.set(ullink.security.krb5.internal.KDCOptions.FORWARDABLE, true);

        ullink.security.krb5.internal.HostAddresses sAddrs = null;
        // XXX Also NT_GSS_KRB5_PRINCIPAL can be a host based principal
        // GSSName.NT_HOSTBASED_SERVICE should display with KRB_NT_SRV_HST
        if (server.getNameType() == ullink.security.krb5.PrincipalName.KRB_NT_SRV_HST)
            sAddrs=  new ullink.security.krb5.internal.HostAddresses(server);

        KrbTgsReq tgsReq = new KrbTgsReq(options, tgt, tgService,
                                         null, null, null, null, sAddrs, null, null, null);
        credMessg = createMessage(tgsReq.sendAndGetCreds(), key);

        obuf = credMessg.asn1Encode();
    }

    ullink.security.krb5.internal.KRBCred createMessage(ullink.security.krb5.Credentials delegatedCreds, ullink.security.krb5.EncryptionKey key)
        throws ullink.security.krb5.KrbException, IOException {

        ullink.security.krb5.EncryptionKey sessionKey
            = delegatedCreds.getSessionKey();
        ullink.security.krb5.PrincipalName princ = delegatedCreds.getClient();
        ullink.security.krb5.Realm realm = princ.getRealm();
        ullink.security.krb5.PrincipalName tgService = delegatedCreds.getServer();
        ullink.security.krb5.Realm tgsRealm = tgService.getRealm();

        ullink.security.krb5.internal.KrbCredInfo credInfo = new ullink.security.krb5.internal.KrbCredInfo(sessionKey, realm,
                                               princ, delegatedCreds.flags, delegatedCreds.authTime,
                                               delegatedCreds.startTime, delegatedCreds.endTime,
                                               delegatedCreds.renewTill, tgsRealm, tgService,
                                               delegatedCreds.cAddr);

        timeStamp = new ullink.security.krb5.internal.KerberosTime(ullink.security.krb5.internal.KerberosTime.NOW);
        ullink.security.krb5.internal.KrbCredInfo[] credInfos = {credInfo};
        ullink.security.krb5.internal.EncKrbCredPart encPart =
            new ullink.security.krb5.internal.EncKrbCredPart(credInfos,
                               timeStamp, null, null, null, null);

        ullink.security.krb5.EncryptedData encEncPart = new ullink.security.krb5.EncryptedData(key,
            encPart.asn1Encode(), KeyUsage.KU_ENC_KRB_CRED_PART);

        ullink.security.krb5.internal.Ticket[] tickets = {delegatedCreds.ticket};

        credMessg = new ullink.security.krb5.internal.KRBCred(tickets, encEncPart);

        return credMessg;
    }

         // Used in InitialToken, key always NULL_KEY
    public KrbCred(byte[] asn1Message, ullink.security.krb5.EncryptionKey key)
        throws ullink.security.krb5.KrbException, IOException {

        credMessg = new ullink.security.krb5.internal.KRBCred(asn1Message);

        ticket = credMessg.tickets[0];

        byte[] temp = credMessg.encPart.decrypt(key,
            KeyUsage.KU_ENC_KRB_CRED_PART);
        byte[] plainText = credMessg.encPart.reset(temp, true);
        DerValue encoding = new DerValue(plainText);
        ullink.security.krb5.internal.EncKrbCredPart encPart = new ullink.security.krb5.internal.EncKrbCredPart(encoding);

        timeStamp = encPart.timeStamp;

        ullink.security.krb5.internal.KrbCredInfo credInfo = encPart.ticketInfo[0];
        ullink.security.krb5.EncryptionKey credInfoKey = credInfo.key;
        ullink.security.krb5.Realm prealm = credInfo.prealm;
        // XXX PrincipalName can store realm + principalname or
        // just principal name.
        ullink.security.krb5.PrincipalName pname = credInfo.pname;
        pname.setRealm(prealm);
        ullink.security.krb5.internal.TicketFlags flags = credInfo.flags;
        ullink.security.krb5.internal.KerberosTime authtime = credInfo.authtime;
        ullink.security.krb5.internal.KerberosTime starttime = credInfo.starttime;
        ullink.security.krb5.internal.KerberosTime endtime = credInfo.endtime;
        ullink.security.krb5.internal.KerberosTime renewTill = credInfo.renewTill;
        ullink.security.krb5.Realm srealm = credInfo.srealm;
        ullink.security.krb5.PrincipalName sname = credInfo.sname;
        sname.setRealm(srealm);
        ullink.security.krb5.internal.HostAddresses caddr = credInfo.caddr;

        if (DEBUG) {
            System.out.println(">>>Delegated Creds have pname=" + pname
                               + " sname=" + sname
                               + " authtime=" + authtime
                               + " starttime=" + starttime
                               + " endtime=" + endtime
                               + "renewTill=" + renewTill);
        }
        creds = new ullink.security.krb5.Credentials(ticket, pname, sname, credInfoKey,
                                flags, authtime, starttime, endtime, renewTill, caddr);
    }

    /**
     * Returns the delegated credentials from the peer.
     */
    public ullink.security.krb5.Credentials[] getDelegatedCreds() {

        ullink.security.krb5.Credentials[] allCreds = {creds};
        return allCreds;
    }

    /**
     * Returns the ASN.1 encoding that should be sent to the peer.
     */
    public byte[] getMessage() {
        return obuf;
    }
}
