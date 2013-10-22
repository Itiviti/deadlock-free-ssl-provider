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

import ullink.security.krb5.internal.crypto.EType;
import ullink.security.krb5.internal.crypto.KeyUsage;
import ullink.security.krb5.internal.crypto.Nonce;

import java.io.IOException;
import java.net.UnknownHostException;

/**
 * This class encapsulates a Kerberos TGS-REQ that is sent from the
 * client to the KDC.
 */
public class KrbTgsReq extends KrbKdcReq {

    private ullink.security.krb5.PrincipalName princName;
    private ullink.security.krb5.PrincipalName servName;
    private ullink.security.krb5.internal.TGSReq tgsReqMessg;
    private ullink.security.krb5.internal.KerberosTime ctime;
    private ullink.security.krb5.internal.Ticket secondTicket = null;
    private boolean useSubkey = false;
    ullink.security.krb5.EncryptionKey tgsReqKey;

    private static final boolean DEBUG = ullink.security.krb5.internal.Krb5.DEBUG;

    private int defaultTimeout = 30*1000; // 30 seconds

     // Used in CredentialsUtil
    public KrbTgsReq(ullink.security.krb5.Credentials asCreds,
                     ullink.security.krb5.PrincipalName sname)
        throws ullink.security.krb5.KrbException, IOException {
        this(new ullink.security.krb5.internal.KDCOptions(),
            asCreds,
            sname,
            null, // KerberosTime from
            null, // KerberosTime till
            null, // KerberosTime rtime
            null, // eTypes, // null, // int[] eTypes
            null, // HostAddresses addresses
            null, // AuthorizationData authorizationData
            null, // Ticket[] additionalTickets
            null); // EncryptionKey subSessionKey
    }

     // Called by Credentials, KrbCred
         KrbTgsReq(
                ullink.security.krb5.internal.KDCOptions options,
                ullink.security.krb5.Credentials asCreds,
                ullink.security.krb5.PrincipalName sname,
                ullink.security.krb5.internal.KerberosTime from,
                ullink.security.krb5.internal.KerberosTime till,
                ullink.security.krb5.internal.KerberosTime rtime,
                int[] eTypes,
                ullink.security.krb5.internal.HostAddresses addresses,
                ullink.security.krb5.internal.AuthorizationData authorizationData,
                ullink.security.krb5.internal.Ticket[] additionalTickets,
                ullink.security.krb5.EncryptionKey subKey) throws ullink.security.krb5.KrbException, IOException {

                princName = asCreds.client;
                servName = sname;
                ctime = new ullink.security.krb5.internal.KerberosTime(ullink.security.krb5.internal.KerberosTime.NOW);


                // check if they are valid arguments. The optional fields
                // should be  consistent with settings in KDCOptions.
                if (options.get(ullink.security.krb5.internal.KDCOptions.FORWARDABLE) &&
                        (!(asCreds.flags.get(ullink.security.krb5.internal.Krb5.TKT_OPTS_FORWARDABLE)))) {
                    throw new ullink.security.krb5.KrbException(ullink.security.krb5.internal.Krb5.KRB_AP_ERR_REQ_OPTIONS);
                }
                if (options.get(ullink.security.krb5.internal.KDCOptions.FORWARDED)) {
                    if (!(asCreds.flags.get(ullink.security.krb5.internal.KDCOptions.FORWARDABLE)))
                        throw new ullink.security.krb5.KrbException(ullink.security.krb5.internal.Krb5.KRB_AP_ERR_REQ_OPTIONS);
                }
                if (options.get(ullink.security.krb5.internal.KDCOptions.PROXIABLE) &&
                        (!(asCreds.flags.get(ullink.security.krb5.internal.Krb5.TKT_OPTS_PROXIABLE)))) {
                    throw new ullink.security.krb5.KrbException(ullink.security.krb5.internal.Krb5.KRB_AP_ERR_REQ_OPTIONS);
                }
                if (options.get(ullink.security.krb5.internal.KDCOptions.PROXY)) {
                    if (!(asCreds.flags.get(ullink.security.krb5.internal.KDCOptions.PROXIABLE)))
                        throw new ullink.security.krb5.KrbException(ullink.security.krb5.internal.Krb5.KRB_AP_ERR_REQ_OPTIONS);
                }
                if (options.get(ullink.security.krb5.internal.KDCOptions.ALLOW_POSTDATE) &&
                        (!(asCreds.flags.get(ullink.security.krb5.internal.Krb5.TKT_OPTS_MAY_POSTDATE)))) {
                    throw new ullink.security.krb5.KrbException(ullink.security.krb5.internal.Krb5.KRB_AP_ERR_REQ_OPTIONS);
                }
                if (options.get(ullink.security.krb5.internal.KDCOptions.RENEWABLE) &&
                        (!(asCreds.flags.get(ullink.security.krb5.internal.Krb5.TKT_OPTS_RENEWABLE)))) {
                    throw new ullink.security.krb5.KrbException(ullink.security.krb5.internal.Krb5.KRB_AP_ERR_REQ_OPTIONS);
                }

                if (options.get(ullink.security.krb5.internal.KDCOptions.POSTDATED)) {
                    if (!(asCreds.flags.get(ullink.security.krb5.internal.KDCOptions.POSTDATED)))
                        throw new ullink.security.krb5.KrbException(ullink.security.krb5.internal.Krb5.KRB_AP_ERR_REQ_OPTIONS);
                } else {
                    if (from != null)  from = null;
                }
                if (options.get(ullink.security.krb5.internal.KDCOptions.RENEWABLE)) {
                    if (!(asCreds.flags.get(ullink.security.krb5.internal.KDCOptions.RENEWABLE)))
                        throw new ullink.security.krb5.KrbException(ullink.security.krb5.internal.Krb5.KRB_AP_ERR_REQ_OPTIONS);
                } else {
                    if (rtime != null)  rtime = null;
                }
                if (options.get(ullink.security.krb5.internal.KDCOptions.ENC_TKT_IN_SKEY)) {
                    if (additionalTickets == null)
                        throw new ullink.security.krb5.KrbException(ullink.security.krb5.internal.Krb5.KRB_AP_ERR_REQ_OPTIONS);
                    // in TGS_REQ there could be more than one additional
                    // tickets,  but in file-based credential cache,
                    // there is only one additional ticket field.
                        secondTicket = additionalTickets[0];
                } else {
                    if (additionalTickets != null)
                        additionalTickets = null;
                }

                tgsReqMessg = createRequest(
                        options,
                        asCreds.ticket,
                        asCreds.key,
                        ctime,
                        princName,
                        princName.getRealm(),
                        servName,
                        from,
                        till,
                        rtime,
                        eTypes,
                        addresses,
                        authorizationData,
                        additionalTickets,
                        subKey);
                obuf = tgsReqMessg.asn1Encode();

                // XXX We need to revisit this to see if can't move it
                // up such that FORWARDED flag set in the options
                // is included in the marshaled request.
                /*
                 * If this is based on a forwarded ticket, record that in the
                 * options, because the returned TgsRep will contain the
                 * FORWARDED flag set.
                 */
                if (asCreds.flags.get(ullink.security.krb5.internal.KDCOptions.FORWARDED))
                    options.set(ullink.security.krb5.internal.KDCOptions.FORWARDED, true);


        }

    /**
     * Sends a TGS request to the realm of the target.
     * @throws ullink.security.krb5.KrbException
     * @throws IOException
     */
    public String send() throws IOException, ullink.security.krb5.KrbException {
        String realmStr = null;
        if (servName != null)
            realmStr = servName.getRealmString();
        return (send(realmStr));
    }

    public ullink.security.krb5.KrbTgsRep getReply()
        throws ullink.security.krb5.KrbException, IOException {
        return new ullink.security.krb5.KrbTgsRep(ibuf, this);
    }

    /**
     * Sends the request, waits for a reply, and returns the Credentials.
     * Used in Credentials, KrbCred, and internal/CredentialsUtil.
     */
    public ullink.security.krb5.Credentials sendAndGetCreds() throws IOException, ullink.security.krb5.KrbException {
        ullink.security.krb5.KrbTgsRep tgs_rep = null;
        String kdc = null;
        try {
            kdc = send();
            tgs_rep = getReply();
        } catch (ullink.security.krb5.KrbException ke) {
            if (ke.returnCode() == ullink.security.krb5.internal.Krb5.KRB_ERR_RESPONSE_TOO_BIG) {
                // set useTCP and retry
                send(servName.getRealmString(), kdc, true);
                tgs_rep = getReply();
            } else {
                throw ke;
            }
        }
        return tgs_rep.getCreds();
    }

    ullink.security.krb5.internal.KerberosTime getCtime() {
        return ctime;
    }

    private ullink.security.krb5.internal.TGSReq createRequest(
                         ullink.security.krb5.internal.KDCOptions kdc_options,
                         ullink.security.krb5.internal.Ticket ticket,
                         ullink.security.krb5.EncryptionKey key,
                         ullink.security.krb5.internal.KerberosTime ctime,
                         ullink.security.krb5.PrincipalName cname,
                         ullink.security.krb5.Realm crealm,
                         ullink.security.krb5.PrincipalName sname,
                         ullink.security.krb5.internal.KerberosTime from,
                         ullink.security.krb5.internal.KerberosTime till,
                         ullink.security.krb5.internal.KerberosTime rtime,
                         int[] eTypes,
                         ullink.security.krb5.internal.HostAddresses addresses,
                         ullink.security.krb5.internal.AuthorizationData authorizationData,
                         ullink.security.krb5.internal.Ticket[] additionalTickets,
                         ullink.security.krb5.EncryptionKey subKey)
        throws ullink.security.krb5.Asn1Exception, IOException, ullink.security.krb5.internal.KdcErrException, ullink.security.krb5.internal.KrbApErrException,
               UnknownHostException, ullink.security.krb5.KrbCryptoException {
        ullink.security.krb5.internal.KerberosTime req_till = null;
        if (till == null) {
            req_till = new ullink.security.krb5.internal.KerberosTime();
        } else {
            req_till = till;
        }

        /*
         * RFC 4120, Section 5.4.2.
         * For KRB_TGS_REP, the ciphertext is encrypted in the
         * sub-session key from the Authenticator, or if absent,
         * the session key from the ticket-granting ticket used
         * in the request.
         *
         * To support this, use tgsReqKey to remember which key to use.
         */
        tgsReqKey = key;

        int[] req_eTypes = null;
        if (eTypes == null) {
            req_eTypes = EType.getDefaults("default_tgs_enctypes");
            if (req_eTypes == null) {
                throw new ullink.security.krb5.KrbCryptoException(
            "No supported encryption types listed in default_tgs_enctypes");
            }
        } else {
            req_eTypes = eTypes;
        }

        ullink.security.krb5.EncryptionKey reqKey = null;
        ullink.security.krb5.EncryptedData encAuthorizationData = null;
        if (authorizationData != null) {
            byte[] ad = authorizationData.asn1Encode();
            if (subKey != null) {
                reqKey = subKey;
                tgsReqKey = subKey;    // Key to use to decrypt reply
                useSubkey = true;
                encAuthorizationData = new ullink.security.krb5.EncryptedData(reqKey, ad,
                    KeyUsage.KU_TGS_REQ_AUTH_DATA_SUBKEY);
            } else
                encAuthorizationData = new ullink.security.krb5.EncryptedData(key, ad,
                    KeyUsage.KU_TGS_REQ_AUTH_DATA_SESSKEY);
        }

        ullink.security.krb5.internal.KDCReqBody reqBody = new ullink.security.krb5.internal.KDCReqBody(
                                            kdc_options,
                                            cname,
                                            // crealm,
                                            sname.getRealm(), // TO
                                            sname,
                                            from,
                                            req_till,
                                            rtime,
                                            Nonce.value(),
                                            req_eTypes,
                                            addresses,
                                            encAuthorizationData,
                                            additionalTickets);

        byte[] temp = reqBody.asn1Encode(ullink.security.krb5.internal.Krb5.KRB_TGS_REQ);
        // if the checksum type is one of the keyed checksum types,
        // use session key.
        ullink.security.krb5.Checksum cksum;
        switch (ullink.security.krb5.Checksum.CKSUMTYPE_DEFAULT) {
        case ullink.security.krb5.Checksum.CKSUMTYPE_RSA_MD4_DES:
        case ullink.security.krb5.Checksum.CKSUMTYPE_DES_MAC:
        case ullink.security.krb5.Checksum.CKSUMTYPE_DES_MAC_K:
        case ullink.security.krb5.Checksum.CKSUMTYPE_RSA_MD4_DES_K:
        case ullink.security.krb5.Checksum.CKSUMTYPE_RSA_MD5_DES:
        case ullink.security.krb5.Checksum.CKSUMTYPE_HMAC_SHA1_DES3_KD:
        case ullink.security.krb5.Checksum.CKSUMTYPE_HMAC_MD5_ARCFOUR:
        case ullink.security.krb5.Checksum.CKSUMTYPE_HMAC_SHA1_96_AES128:
        case ullink.security.krb5.Checksum.CKSUMTYPE_HMAC_SHA1_96_AES256:
            cksum = new ullink.security.krb5.Checksum(ullink.security.krb5.Checksum.CKSUMTYPE_DEFAULT, temp, key,
                KeyUsage.KU_PA_TGS_REQ_CKSUM);
            break;
        case ullink.security.krb5.Checksum.CKSUMTYPE_CRC32:
        case ullink.security.krb5.Checksum.CKSUMTYPE_RSA_MD4:
        case ullink.security.krb5.Checksum.CKSUMTYPE_RSA_MD5:
        default:
            cksum = new ullink.security.krb5.Checksum(ullink.security.krb5.Checksum.CKSUMTYPE_DEFAULT, temp);
        }

        // Usage will be KeyUsage.KU_PA_TGS_REQ_AUTHENTICATOR

        byte[] tgs_ap_req = new ullink.security.krb5.KrbApReq(
                                         new ullink.security.krb5.internal.APOptions(),
                                         ticket,
                                         key,
                                         crealm,
                                         cname,
                                         cksum,
                                         ctime,
                                         reqKey,
                                         null,
                                         null).getMessage();

        ullink.security.krb5.internal.PAData[] tgsPAData = new ullink.security.krb5.internal.PAData[1];
        tgsPAData[0] = new ullink.security.krb5.internal.PAData(ullink.security.krb5.internal.Krb5.PA_TGS_REQ, tgs_ap_req);

        return new ullink.security.krb5.internal.TGSReq(tgsPAData, reqBody);
    }

    ullink.security.krb5.internal.TGSReq getMessage() {
        return tgsReqMessg;
    }

    ullink.security.krb5.internal.Ticket getSecondTicket() {
        return secondTicket;
    }

    private static void debug(String message) {
        //      System.err.println(">>> KrbTgsReq: " + message);
    }

    boolean usedSubkey() {
        return useSubkey;
    }

}
