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

/*
 *  (C) Copyright IBM Corp. 1999 All Rights Reserved.
 *  Copyright 1997 The Open Group Research Institute.  All rights reserved.
 */

package ullink.security.krb5;

import ullink.security.krb5.internal.crypto.EType;
import ullink.security.krb5.internal.crypto.KeyUsage;
import ullink.security.krb5.internal.rcache.AuthTime;
import ullink.security.krb5.internal.rcache.CacheTable;
import ullink.security.util.DerValue;

import java.io.IOException;
import java.net.InetAddress;

/**
 * This class encapsulates a KRB-AP-REQ that a client sends to a
 * server for authentication.
 */
public class KrbApReq {

    private byte[] obuf;
    private ullink.security.krb5.internal.KerberosTime ctime;
    private int cusec;
    private ullink.security.krb5.internal.Authenticator authenticator;
    private ullink.security.krb5.Credentials creds;
    private ullink.security.krb5.internal.APReq apReqMessg;

    private static CacheTable table = new CacheTable();
    private static boolean DEBUG = ullink.security.krb5.internal.Krb5.DEBUG;

    // default is address-less tickets
    private boolean KDC_EMPTY_ADDRESSES_ALLOWED = true;

    /**
     * Contructs a AP-REQ message to send to the peer.
     * @param tgsCred the <code>Credentials</code> to be used to construct the
     *          AP Request  protocol message.
     * @param mutualRequired Whether mutual authentication is required
     * @param useSubkey Whether the subkey is to be used to protect this
     *        specific application session. If this is not set then the
     *        session key from the ticket will be used.
     * @throws ullink.security.krb5.KrbException for any Kerberos protocol specific error
     * @throws IOException for any IO related errors
     *          (e.g. socket operations)
     */
     /*
     // Not Used
    public KrbApReq(Credentials tgsCred,
                    boolean mutualRequired,
                    boolean useSubKey,
                    boolean useSeqNumber) throws Asn1Exception,
                    KrbCryptoException, KrbException, IOException {

        this(tgsCred, mutualRequired, useSubKey, useSeqNumber, null);
    }
*/

    /**
     * Contructs a AP-REQ message to send to the peer.
     * @param tgsCred the <code>Credentials</code> to be used to construct the
     *          AP Request  protocol message.
     * @param mutualRequired Whether mutual authentication is required
     * @param useSubkey Whether the subkey is to be used to protect this
     *        specific application session. If this is not set then the
     *        session key from the ticket will be used.
     * @param checksum checksum of the the application data that accompanies
     *        the KRB_AP_REQ.
     * @throws ullink.security.krb5.KrbException for any Kerberos protocol specific error
     * @throws IOException for any IO related errors
     *          (e.g. socket operations)
     */
     // Used in InitSecContextToken
    public KrbApReq(ullink.security.krb5.Credentials tgsCred,
                    boolean mutualRequired,
                    boolean useSubKey,
                    boolean useSeqNumber,
                    ullink.security.krb5.Checksum cksum) throws ullink.security.krb5.Asn1Exception,
            ullink.security.krb5.KrbCryptoException, ullink.security.krb5.KrbException, IOException  {

        ullink.security.krb5.internal.APOptions apOptions = (mutualRequired?
                               new ullink.security.krb5.internal.APOptions(ullink.security.krb5.internal.Krb5.AP_OPTS_MUTUAL_REQUIRED):
                               new ullink.security.krb5.internal.APOptions());
        if (DEBUG)
            System.out.println(">>> KrbApReq: APOptions are " + apOptions);

        ullink.security.krb5.EncryptionKey subKey = (useSubKey?
                                new ullink.security.krb5.EncryptionKey(tgsCred.getSessionKey()):
                                null);

        ullink.security.krb5.internal.SeqNumber seqNum = new ullink.security.krb5.internal.LocalSeqNumber();

        init(apOptions,
             tgsCred,
             cksum,
             subKey,
             seqNum,
             null,   // AuthorizationData authzData
            KeyUsage.KU_AP_REQ_AUTHENTICATOR);

    }

    /**
     * Contructs a AP-REQ message from the bytes received from the
     * peer.
     * @param message The message received from the peer
     * @param keys <code>EncrtyptionKey</code>s to decrypt the message;
     *       key selected will depend on etype used to encrypte data
     * @throws ullink.security.krb5.KrbException for any Kerberos protocol specific error
     * @throws IOException for any IO related errors
     *          (e.g. socket operations)
     */
     // Used in InitSecContextToken (for AP_REQ and not TGS REQ)
    public KrbApReq(byte[] message,
                    ullink.security.krb5.EncryptionKey[] keys,
                    InetAddress initiator)
        throws ullink.security.krb5.KrbException, IOException {
        obuf = message;
        if (apReqMessg == null)
            decode();
        authenticate(keys, initiator);
    }

    /**
     * Contructs a AP-REQ message from the bytes received from the
     * peer.
     * @param value The <code>DerValue</code> that contains the
     *              DER enoded AP-REQ protocol message
     * @param keys <code>EncrtyptionKey</code>s to decrypt the message;
     *
     * @throws ullink.security.krb5.KrbException for any Kerberos protocol specific error
     * @throws IOException for any IO related errors
     *          (e.g. socket operations)
     */
     /*
    public KrbApReq(DerValue value, EncryptionKey[] key, InetAddress initiator)
        throws KrbException, IOException {
        obuf = value.toByteArray();
        if (apReqMessg == null)
            decode(value);
        authenticate(keys, initiator);
    }

    KrbApReq(APOptions options,
             Credentials tgs_creds,
             Checksum cksum,
             EncryptionKey subKey,
             SeqNumber seqNumber,
             AuthorizationData authorizationData)
        throws KrbException, IOException {
        init(options, tgs_creds, cksum, subKey, seqNumber, authorizationData);
    }
*/

     /** used by KrbTgsReq **/
    KrbApReq(ullink.security.krb5.internal.APOptions apOptions,
             ullink.security.krb5.internal.Ticket ticket,
             ullink.security.krb5.EncryptionKey key,
             ullink.security.krb5.Realm crealm,
             ullink.security.krb5.PrincipalName cname,
             ullink.security.krb5.Checksum cksum,
             ullink.security.krb5.internal.KerberosTime ctime,
             ullink.security.krb5.EncryptionKey subKey,
             ullink.security.krb5.internal.SeqNumber seqNumber,
        ullink.security.krb5.internal.AuthorizationData authorizationData)
        throws ullink.security.krb5.Asn1Exception, IOException,
            ullink.security.krb5.internal.KdcErrException, ullink.security.krb5.KrbCryptoException {

        init(apOptions, ticket, key, crealm, cname,
             cksum, ctime, subKey, seqNumber, authorizationData,
            KeyUsage.KU_PA_TGS_REQ_AUTHENTICATOR);

    }

    private void init(ullink.security.krb5.internal.APOptions options,
                      ullink.security.krb5.Credentials tgs_creds,
                      ullink.security.krb5.Checksum cksum,
                      ullink.security.krb5.EncryptionKey subKey,
                      ullink.security.krb5.internal.SeqNumber seqNumber,
                      ullink.security.krb5.internal.AuthorizationData authorizationData,
        int usage)
        throws ullink.security.krb5.KrbException, IOException {

        ctime = new ullink.security.krb5.internal.KerberosTime(ullink.security.krb5.internal.KerberosTime.NOW);
        init(options,
             tgs_creds.ticket,
             tgs_creds.key,
             tgs_creds.client.getRealm(),
             tgs_creds.client,
             cksum,
             ctime,
             subKey,
             seqNumber,
             authorizationData,
            usage);
    }

    private void init(ullink.security.krb5.internal.APOptions apOptions,
                      ullink.security.krb5.internal.Ticket ticket,
                      ullink.security.krb5.EncryptionKey key,
                      ullink.security.krb5.Realm crealm,
                      ullink.security.krb5.PrincipalName cname,
                      ullink.security.krb5.Checksum cksum,
                      ullink.security.krb5.internal.KerberosTime ctime,
                      ullink.security.krb5.EncryptionKey subKey,
                      ullink.security.krb5.internal.SeqNumber seqNumber,
                      ullink.security.krb5.internal.AuthorizationData authorizationData,
        int usage)
        throws ullink.security.krb5.Asn1Exception, IOException,
            ullink.security.krb5.internal.KdcErrException, ullink.security.krb5.KrbCryptoException {

        createMessage(apOptions, ticket, key, crealm, cname,
                      cksum, ctime, subKey, seqNumber, authorizationData,
            usage);
        obuf = apReqMessg.asn1Encode();
    }


    void decode() throws ullink.security.krb5.KrbException, IOException {
        DerValue encoding = new DerValue(obuf);
        decode(encoding);
    }

    void decode(DerValue encoding) throws ullink.security.krb5.KrbException, IOException {
        apReqMessg = null;
        try {
            apReqMessg = new ullink.security.krb5.internal.APReq(encoding);
        } catch (ullink.security.krb5.Asn1Exception e) {
            apReqMessg = null;
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
    }

    private void authenticate(ullink.security.krb5.EncryptionKey[] keys, InetAddress initiator)
        throws ullink.security.krb5.KrbException, IOException {
        int encPartKeyType = apReqMessg.ticket.encPart.getEType();
        ullink.security.krb5.EncryptionKey dkey = ullink.security.krb5.EncryptionKey.findKey(encPartKeyType, keys);

        if (dkey == null) {
            throw new ullink.security.krb5.KrbException(ullink.security.krb5.internal.Krb5.API_INVALID_ARG,
                "Cannot find key of appropriate type to decrypt AP REP - " +
                                   EType.toString(encPartKeyType));
        }

        byte[] bytes = apReqMessg.ticket.encPart.decrypt(dkey,
            KeyUsage.KU_TICKET);
        byte[] temp = apReqMessg.ticket.encPart.reset(bytes, true);
        ullink.security.krb5.internal.EncTicketPart enc_ticketPart = new ullink.security.krb5.internal.EncTicketPart(temp);

        checkPermittedEType(enc_ticketPart.key.getEType());

        byte[] bytes2 = apReqMessg.authenticator.decrypt(enc_ticketPart.key,
            KeyUsage.KU_AP_REQ_AUTHENTICATOR);
        byte[] temp2 = apReqMessg.authenticator.reset(bytes2, true);
        authenticator = new ullink.security.krb5.internal.Authenticator(temp2);
        ctime = authenticator.ctime;
        cusec = authenticator.cusec;
        authenticator.ctime.setMicroSeconds(authenticator.cusec);
        authenticator.cname.setRealm(authenticator.crealm);
        apReqMessg.ticket.sname.setRealm(apReqMessg.ticket.realm);
        enc_ticketPart.cname.setRealm(enc_ticketPart.crealm);

        Config.getInstance().resetDefaultRealm(apReqMessg.ticket.realm.toString());

        if (!authenticator.cname.equals(enc_ticketPart.cname))
            throw new ullink.security.krb5.internal.KrbApErrException(ullink.security.krb5.internal.Krb5.KRB_AP_ERR_BADMATCH);

        ullink.security.krb5.internal.KerberosTime currTime = new ullink.security.krb5.internal.KerberosTime(ullink.security.krb5.internal.KerberosTime.NOW);
        if (!authenticator.ctime.inClockSkew(currTime))
            throw new ullink.security.krb5.internal.KrbApErrException(ullink.security.krb5.internal.Krb5.KRB_AP_ERR_SKEW);

        // start to check if it is a replay attack.
        AuthTime time =
            new AuthTime(authenticator.ctime.getTime(), authenticator.cusec);
        String client = authenticator.cname.toString();
        if (table.get(time, authenticator.cname.toString()) != null) {
            throw new ullink.security.krb5.internal.KrbApErrException(ullink.security.krb5.internal.Krb5.KRB_AP_ERR_REPEAT);
        } else {
            table.put(client, time, currTime.getTime());
        }

        // check to use addresses in tickets
        if (Config.getInstance().useAddresses()) {
            KDC_EMPTY_ADDRESSES_ALLOWED = false;
        }

        // sender host address
        ullink.security.krb5.internal.HostAddress sender = null;
        if (initiator != null) {
            sender = new ullink.security.krb5.internal.HostAddress(initiator);
        }

        if (sender != null || !KDC_EMPTY_ADDRESSES_ALLOWED) {
            if (enc_ticketPart.caddr != null) {
                if (sender == null)
                    throw new ullink.security.krb5.internal.KrbApErrException(ullink.security.krb5.internal.Krb5.KRB_AP_ERR_BADADDR);
                if (!enc_ticketPart.caddr.inList(sender))
                    throw new ullink.security.krb5.internal.KrbApErrException(ullink.security.krb5.internal.Krb5.KRB_AP_ERR_BADADDR);
            }
        }

        // XXX check for repeated authenticator
        // if found
        //    throw new KrbApErrException(Krb5.KRB_AP_ERR_REPEAT);
        // else
        //    save authenticator to check for later

        ullink.security.krb5.internal.KerberosTime now = new ullink.security.krb5.internal.KerberosTime(ullink.security.krb5.internal.KerberosTime.NOW);

        if ((enc_ticketPart.starttime != null &&
             enc_ticketPart.starttime.greaterThanWRTClockSkew(now)) ||
            enc_ticketPart.flags.get(ullink.security.krb5.internal.Krb5.TKT_OPTS_INVALID))
            throw new ullink.security.krb5.internal.KrbApErrException(ullink.security.krb5.internal.Krb5.KRB_AP_ERR_TKT_NYV);

        // if the current time is later than end time by more
        // than the allowable clock skew, throws ticket expired exception.
        if (enc_ticketPart.endtime != null &&
            now.greaterThanWRTClockSkew(enc_ticketPart.endtime)) {
            throw new ullink.security.krb5.internal.KrbApErrException(ullink.security.krb5.internal.Krb5.KRB_AP_ERR_TKT_EXPIRED);
        }

        creds = new ullink.security.krb5.Credentials(
                                apReqMessg.ticket,
                                authenticator.cname,
                                apReqMessg.ticket.sname,
                                enc_ticketPart.key,
                                null,
                                enc_ticketPart.authtime,
                                enc_ticketPart.starttime,
                                enc_ticketPart.endtime,
                                enc_ticketPart.renewTill,
                                enc_ticketPart.caddr);
        if (DEBUG) {
            System.out.println(">>> KrbApReq: authenticate succeed.");
        }
    }

    /**
     * Returns the credentials that are contained in the ticket that
     * is part of this this AP-REP.
     */
    public ullink.security.krb5.Credentials getCreds() {
        return creds;
    }

    ullink.security.krb5.internal.KerberosTime getCtime() {
        if (ctime != null)
            return ctime;
        return authenticator.ctime;
    }

    int cusec() {
        return cusec;
    }

    ullink.security.krb5.internal.APOptions getAPOptions() throws ullink.security.krb5.KrbException, IOException {
        if (apReqMessg == null)
            decode();
        if (apReqMessg != null)
            return apReqMessg.apOptions;
        return null;
    }

    /**
     * Returns true if mutual authentication is required and hence an
     * AP-REP will need to be generated.
     * @throws ullink.security.krb5.KrbException
     * @throws IOException
     */
    public boolean getMutualAuthRequired() throws ullink.security.krb5.KrbException, IOException {
        if (apReqMessg == null)
            decode();
        if (apReqMessg != null)
            return apReqMessg.apOptions.get(ullink.security.krb5.internal.Krb5.AP_OPTS_MUTUAL_REQUIRED);
        return false;
    }

    boolean useSessionKey() throws ullink.security.krb5.KrbException, IOException {
        if (apReqMessg == null)
            decode();
        if (apReqMessg != null)
            return apReqMessg.apOptions.get(ullink.security.krb5.internal.Krb5.AP_OPTS_USE_SESSION_KEY);
        return false;
    }

    /**
     * Returns the optional subkey stored in the Authenticator for
     * this message. Returns null if none is stored.
     */
    public ullink.security.krb5.EncryptionKey getSubKey() {
        // XXX Can authenticator be null
        return authenticator.getSubKey();
    }

    /**
     * Returns the optional sequence number stored in the
     * Authenticator for this message. Returns null if none is
     * stored.
     */
    public Integer getSeqNumber() {
        // XXX Can authenticator be null
        return authenticator.getSeqNumber();
    }

    /**
     * Returns the optional Checksum stored in the
     * Authenticator for this message. Returns null if none is
     * stored.
     */
    public ullink.security.krb5.Checksum getChecksum() {
        return authenticator.getChecksum();
    }

    /**
     * Returns the ASN.1 encoding that should be sent to the peer.
     */
    public byte[] getMessage() {
        return obuf;
    }

    /**
     * Returns the principal name of the client that generated this
     * message.
     */
    public ullink.security.krb5.PrincipalName getClient() {
        return creds.getClient();
    }

    private void createMessage(ullink.security.krb5.internal.APOptions apOptions,
                               ullink.security.krb5.internal.Ticket ticket,
                               ullink.security.krb5.EncryptionKey key,
                               ullink.security.krb5.Realm crealm,
                               ullink.security.krb5.PrincipalName cname,
                               ullink.security.krb5.Checksum cksum,
                               ullink.security.krb5.internal.KerberosTime ctime,
                               ullink.security.krb5.EncryptionKey subKey,
                               ullink.security.krb5.internal.SeqNumber seqNumber,
                               ullink.security.krb5.internal.AuthorizationData authorizationData,
        int usage)
        throws ullink.security.krb5.Asn1Exception, IOException,
            ullink.security.krb5.internal.KdcErrException, ullink.security.krb5.KrbCryptoException {

        Integer seqno = null;

        if (seqNumber != null)
            seqno = new Integer(seqNumber.current());

        authenticator =
            new ullink.security.krb5.internal.Authenticator(crealm,
                              cname,
                              cksum,
                              ctime.getMicroSeconds(),
                              ctime,
                              subKey,
                              seqno,
                              authorizationData);

        byte[] temp = authenticator.asn1Encode();

        ullink.security.krb5.EncryptedData encAuthenticator =
            new ullink.security.krb5.EncryptedData(key, temp, usage);

        apReqMessg =
            new ullink.security.krb5.internal.APReq(apOptions, ticket, encAuthenticator);
    }

     // Check that key is one of the permitted types
     private static void checkPermittedEType(int target) throws ullink.security.krb5.KrbException {
        int[] etypes = EType.getDefaults("permitted_enctypes");
        if (etypes == null) {
            throw new ullink.security.krb5.KrbException(
                "No supported encryption types listed in permitted_enctypes");
        }
        if (!EType.isSupported(target, etypes)) {
            throw new ullink.security.krb5.KrbException(EType.toString(target) +
                " encryption type not in permitted_enctypes list");
        }
     }
}
