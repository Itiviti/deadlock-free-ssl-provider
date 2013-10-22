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
import ullink.security.krb5.internal.crypto.Nonce;

import java.io.IOException;
import java.net.UnknownHostException;

/**
 * This class encapsulates the KRB-AS-REQ message that the client
 * sends to the KDC.
 */
public class KrbAsReq extends KrbKdcReq {
    private ullink.security.krb5.PrincipalName princName;
    private ullink.security.krb5.internal.ASReq asReqMessg;

    private boolean DEBUG = ullink.security.krb5.internal.Krb5.DEBUG;
    private static ullink.security.krb5.internal.KDCOptions defaultKDCOptions = new ullink.security.krb5.internal.KDCOptions();

    // pre-auth info
    private boolean PA_ENC_TIMESTAMP_REQUIRED = false;
    private boolean pa_exists = false;
    private int pa_etype = 0;
    private byte[] pa_salt = null;
    private byte[] pa_s2kparams = null;

    // default is address-less tickets
    private boolean KDC_EMPTY_ADDRESSES_ALLOWED = true;

    /**
     * Creates a KRB-AS-REQ to send to the default KDC
     * @throws ullink.security.krb5.KrbException
     * @throws IOException
     */
     // Called by Credentials
    KrbAsReq(ullink.security.krb5.PrincipalName principal, ullink.security.krb5.EncryptionKey[] keys)
        throws ullink.security.krb5.KrbException, IOException {
        this(keys, // for pre-authentication
             false, 0, null, null, // pre-auth values
             defaultKDCOptions,
             principal,
             null, // PrincipalName sname
             null, // KerberosTime from
             null, // KerberosTime till
             null, // KerberosTime rtime
             null, // int[] eTypes
             null, // HostAddresses addresses
             null); // Ticket[] additionalTickets
    }

    /**
     * Creates a KRB-AS-REQ to send to the default KDC
     * with pre-authentication values
     */
    KrbAsReq(ullink.security.krb5.PrincipalName principal, ullink.security.krb5.EncryptionKey[] keys,
        boolean pa_exists, int etype, byte[] salt, byte[] s2kparams)
        throws ullink.security.krb5.KrbException, IOException {
        this(keys, // for pre-authentication
             pa_exists, etype, salt, s2kparams, // pre-auth values
             defaultKDCOptions,
             principal,
             null, // PrincipalName sname
             null, // KerberosTime from
             null, // KerberosTime till
             null, // KerberosTime rtime
             null, // int[] eTypes
             null, // HostAddresses addresses
             null); // Ticket[] additionalTickets
    }

     private static int[] getETypesFromKeys(ullink.security.krb5.EncryptionKey[] keys) {
         int[] types = new int[keys.length];
         for (int i = 0; i < keys.length; i++) {
             types[i] = keys[i].getEType();
         }
         return types;
     }

    // update with pre-auth info
    public void updatePA(int etype, byte[] salt, byte[] params, ullink.security.krb5.PrincipalName name) {
        // set the pre-auth values
        pa_exists = true;
        pa_etype = etype;
        pa_salt = salt;
        pa_s2kparams = params;

        // update salt in PrincipalName
        if (salt != null && salt.length > 0) {
            String newSalt = new String(salt);
            name.setSalt(newSalt);
            if (DEBUG) {
                System.out.println("Updated salt from pre-auth = " + name.getSalt());
            }
        }
        PA_ENC_TIMESTAMP_REQUIRED = true;
    }

     // Used by Kinit
    public KrbAsReq(
                    char[] password,
                    ullink.security.krb5.internal.KDCOptions options,
                    ullink.security.krb5.PrincipalName cname,
                    ullink.security.krb5.PrincipalName sname,
                    ullink.security.krb5.internal.KerberosTime from,
                    ullink.security.krb5.internal.KerberosTime till,
                    ullink.security.krb5.internal.KerberosTime rtime,
                    int[] eTypes,
                    ullink.security.krb5.internal.HostAddresses addresses,
                    ullink.security.krb5.internal.Ticket[] additionalTickets)
        throws ullink.security.krb5.KrbException, IOException {
        this(password,
             false, 0, null, null, // pre-auth values
             options,
             cname,
             sname, // PrincipalName sname
             from,  // KerberosTime from
             till,  // KerberosTime till
             rtime, // KerberosTime rtime
             eTypes, // int[] eTypes
             addresses, // HostAddresses addresses
             additionalTickets); // Ticket[] additionalTickets
    }

     // Used by Kinit
    public KrbAsReq(
                    char[] password,
                    boolean pa_exists,
                    int etype,
                    byte[] salt,
                    byte[] s2kparams,
                    ullink.security.krb5.internal.KDCOptions options,
                    ullink.security.krb5.PrincipalName cname,
                    ullink.security.krb5.PrincipalName sname,
                    ullink.security.krb5.internal.KerberosTime from,
                    ullink.security.krb5.internal.KerberosTime till,
                    ullink.security.krb5.internal.KerberosTime rtime,
                    int[] eTypes,
                    ullink.security.krb5.internal.HostAddresses addresses,
                    ullink.security.krb5.internal.Ticket[] additionalTickets)
        throws ullink.security.krb5.KrbException, IOException {

        ullink.security.krb5.EncryptionKey[] keys = null;

        // update with preauth info
        if (pa_exists) {
            updatePA(etype, salt, s2kparams, cname);
        }

        if (password != null) {
            keys = ullink.security.krb5.EncryptionKey.acquireSecretKeys(password, cname.getSalt(), pa_exists,
                    pa_etype, pa_s2kparams);
        }
        if (DEBUG) {
            System.out.println(">>>KrbAsReq salt is " + cname.getSalt());
        }

        try {
            init(
                 keys,
                 options,
                 cname,
                 sname,
                 from,
                 till,
                 rtime,
                 eTypes,
                 addresses,
                 additionalTickets);
        }
        finally {
            /*
             * Its ok to destroy the key here because we created it and are
             * now done with it.
             */
             if (keys != null) {
                 for (int i = 0; i < keys.length; i++) {
                     keys[i].destroy();
                 }
             }
        }
    }

     // Used in Kinit
    public KrbAsReq(
                    ullink.security.krb5.EncryptionKey[] keys,
                    ullink.security.krb5.internal.KDCOptions options,
                    ullink.security.krb5.PrincipalName cname,
                    ullink.security.krb5.PrincipalName sname,
                    ullink.security.krb5.internal.KerberosTime from,
                    ullink.security.krb5.internal.KerberosTime till,
                    ullink.security.krb5.internal.KerberosTime rtime,
                    int[] eTypes,
                    ullink.security.krb5.internal.HostAddresses addresses,
                    ullink.security.krb5.internal.Ticket[] additionalTickets)
        throws ullink.security.krb5.KrbException, IOException {
        this(keys,
             false, 0, null, null, // pre-auth values
             options,
             cname,
             sname, // PrincipalName sname
             from,  // KerberosTime from
             till,  // KerberosTime till
             rtime, // KerberosTime rtime
             eTypes, // int[] eTypes
             addresses, // HostAddresses addresses
             additionalTickets); // Ticket[] additionalTickets
    }

    // Used by Kinit
    public KrbAsReq(
                    ullink.security.krb5.EncryptionKey[] keys,
                    boolean pa_exists,
                    int etype,
                    byte[] salt,
                    byte[] s2kparams,
                    ullink.security.krb5.internal.KDCOptions options,
                    ullink.security.krb5.PrincipalName cname,
                    ullink.security.krb5.PrincipalName sname,
                    ullink.security.krb5.internal.KerberosTime from,
                    ullink.security.krb5.internal.KerberosTime till,
                    ullink.security.krb5.internal.KerberosTime rtime,
                    int[] eTypes,
                    ullink.security.krb5.internal.HostAddresses addresses,
                    ullink.security.krb5.internal.Ticket[] additionalTickets)
        throws ullink.security.krb5.KrbException, IOException {

        // update with preauth info
        if (pa_exists) {
            // update pre-auth info
            updatePA(etype, salt, s2kparams, cname);

            if (DEBUG) {
                System.out.println(">>>KrbAsReq salt is " + cname.getSalt());
            }
        }

        init(
             keys,
             options,
             cname,
             sname,
             from,
             till,
             rtime,
             eTypes,
             addresses,
             additionalTickets);
    }

     /*
    private KrbAsReq(KDCOptions options,
             PrincipalName cname,
             PrincipalName sname,
             KerberosTime from,
             KerberosTime till,
             KerberosTime rtime,
             int[] eTypes,
             HostAddresses addresses,
             Ticket[] additionalTickets)
        throws KrbException, IOException {
        init(null,
             options,
             cname,
             sname,
             from,
             till,
             rtime,
             eTypes,
             addresses,
             additionalTickets);
    }
*/

    private void init(ullink.security.krb5.EncryptionKey[] keys,
                      ullink.security.krb5.internal.KDCOptions options,
                      ullink.security.krb5.PrincipalName cname,
                      ullink.security.krb5.PrincipalName sname,
                      ullink.security.krb5.internal.KerberosTime from,
                      ullink.security.krb5.internal.KerberosTime till,
                      ullink.security.krb5.internal.KerberosTime rtime,
                      int[] eTypes,
                      ullink.security.krb5.internal.HostAddresses addresses,
                      ullink.security.krb5.internal.Ticket[] additionalTickets )
        throws ullink.security.krb5.KrbException, IOException {

        // check if they are valid arguments. The optional fields should be
        // consistent with settings in KDCOptions. Mar 17 2000
        if (options.get(ullink.security.krb5.internal.KDCOptions.FORWARDED) ||
            options.get(ullink.security.krb5.internal.KDCOptions.PROXY) ||
            options.get(ullink.security.krb5.internal.KDCOptions.ENC_TKT_IN_SKEY) ||
            options.get(ullink.security.krb5.internal.KDCOptions.RENEW) ||
            options.get(ullink.security.krb5.internal.KDCOptions.VALIDATE)) {
            // this option is only specified in a request to the
            // ticket-granting server
            throw new ullink.security.krb5.KrbException(ullink.security.krb5.internal.Krb5.KRB_AP_ERR_REQ_OPTIONS);
        }
        if (options.get(ullink.security.krb5.internal.KDCOptions.POSTDATED)) {
            //  if (from == null)
            //          throw new KrbException(Krb5.KRB_AP_ERR_REQ_OPTIONS);
        } else {
            if (from != null)  from = null;
        }
        if (options.get(ullink.security.krb5.internal.KDCOptions.RENEWABLE)) {
            //  if (rtime == null)
            //          throw new KrbException(Krb5.KRB_AP_ERR_REQ_OPTIONS);
        } else {
            if (rtime != null)  rtime = null;
        }

        princName = cname;

        ullink.security.krb5.EncryptionKey key = null;
        int[] tktETypes = null;
        if (pa_exists && pa_etype != ullink.security.krb5.EncryptedData.ETYPE_NULL) {
            if (DEBUG) {
                System.out.println("Pre-Authenticaton: find key for etype = " + pa_etype);
            }
            key = ullink.security.krb5.EncryptionKey.findKey(pa_etype, keys);
            tktETypes = new int[1];
            tktETypes[0] = pa_etype;
        } else {
            tktETypes = EType.getDefaults("default_tkt_enctypes", keys);
            key = ullink.security.krb5.EncryptionKey.findKey(tktETypes[0], keys);
        }

        ullink.security.krb5.internal.PAData[] paData = null;
        if (PA_ENC_TIMESTAMP_REQUIRED) {
            if (DEBUG) {
                System.out.println("AS-REQ: Add PA_ENC_TIMESTAMP now");
            }
            ullink.security.krb5.internal.PAEncTSEnc ts = new ullink.security.krb5.internal.PAEncTSEnc();
            byte[] temp = ts.asn1Encode();
            if (key != null) {
                // Use first key in list
                ullink.security.krb5.EncryptedData encTs = new ullink.security.krb5.EncryptedData(key, temp,
                    KeyUsage.KU_PA_ENC_TS);
                paData = new ullink.security.krb5.internal.PAData[1];
                paData[0] = new ullink.security.krb5.internal.PAData( ullink.security.krb5.internal.Krb5.PA_ENC_TIMESTAMP,
                                        encTs.asn1Encode());
            }
        }

        if (DEBUG) {
            System.out.println(">>> KrbAsReq calling createMessage");
        }

        if (eTypes == null) {
            eTypes = tktETypes;
        }

        // check to use addresses in tickets
        if (ullink.security.krb5.Config.getInstance().useAddresses()) {
            KDC_EMPTY_ADDRESSES_ALLOWED = false;
        }
        // get the local InetAddress if required
        if (addresses == null && !KDC_EMPTY_ADDRESSES_ALLOWED) {
            addresses = ullink.security.krb5.internal.HostAddresses.getLocalAddresses();
        }

        asReqMessg = createMessage(
                                   paData,
                                   options,
                                   cname,
                                   cname.getRealm(),
                                   sname,
                                   from,
                                   till,
                                   rtime,
                                   eTypes,
                                   addresses,
                                   additionalTickets);
        obuf = asReqMessg.asn1Encode();
    }

    /**
     * Returns an AS-REP message corresponding to the AS-REQ that
     * was sent.
     * @param password The password that will be used to derive the
     * secret key that will decrypt the AS-REP from  the KDC.
     * @exception ullink.security.krb5.KrbException if an error occurs while reading the data.
     * @exception IOException if an I/O error occurs while reading encoded data.
     */
    public ullink.security.krb5.KrbAsRep getReply(char[] password)
        throws ullink.security.krb5.KrbException, IOException {

        if (password == null)
            throw new ullink.security.krb5.KrbException(ullink.security.krb5.internal.Krb5.API_INVALID_ARG);
        ullink.security.krb5.KrbAsRep temp = null;
        ullink.security.krb5.EncryptionKey[] keys = null;
        try {
            keys = ullink.security.krb5.EncryptionKey.acquireSecretKeys(password,
                    princName.getSalt(), pa_exists, pa_etype, pa_s2kparams);
            temp = getReply(keys);
        } finally {
            /*
             * Its ok to destroy the key here because we created it and are
             * now done with it.
             */
             if (keys != null) {
                for (int i = 0; i < keys.length; i++) {
                    keys[i].destroy();
                }
             }
        }
        return temp;
    }

    /**
     * Sends an AS request to the realm of the client.
     * returns the KDC hostname that the request was sent to
     */

    public String send()
        throws IOException, ullink.security.krb5.KrbException
    {
        String realmStr = null;
        if (princName != null)
            realmStr = princName.getRealmString();

        return (send(realmStr));
    }

    /**
     * Returns an AS-REP message corresponding to the AS-REQ that
     * was sent.
     * @param keys The secret keys that will decrypt the AS-REP from
     * the KDC; key selected depends on etype used to encrypt data.
     * @exception ullink.security.krb5.KrbException if an error occurs while reading the data.
     * @exception IOException if an I/O error occurs while reading encoded
     * data.
     *
     */
    public ullink.security.krb5.KrbAsRep getReply(ullink.security.krb5.EncryptionKey[] keys)
        throws ullink.security.krb5.KrbException,IOException {
        return new ullink.security.krb5.KrbAsRep(ibuf, keys, this);
    }

    private ullink.security.krb5.internal.ASReq createMessage(
                        ullink.security.krb5.internal.PAData[] paData,
                        ullink.security.krb5.internal.KDCOptions kdc_options,
                        ullink.security.krb5.PrincipalName cname,
                        ullink.security.krb5.Realm crealm,
                        ullink.security.krb5.PrincipalName sname,
                        ullink.security.krb5.internal.KerberosTime from,
                        ullink.security.krb5.internal.KerberosTime till,
                        ullink.security.krb5.internal.KerberosTime rtime,
                        int[] eTypes,
                        ullink.security.krb5.internal.HostAddresses addresses,
                        ullink.security.krb5.internal.Ticket[] additionalTickets
                        ) throws ullink.security.krb5.Asn1Exception, ullink.security.krb5.internal.KrbApErrException,
            ullink.security.krb5.RealmException, UnknownHostException, IOException {

        if (DEBUG) {
            System.out.println(">>> KrbAsReq in createMessage");
        }

        ullink.security.krb5.PrincipalName req_sname = null;
        if (sname == null) {
            if (crealm == null) {
                throw new ullink.security.krb5.RealmException(ullink.security.krb5.internal.Krb5.REALM_NULL,
                                         "default realm not specified ");
            }
            req_sname = new ullink.security.krb5.PrincipalName(
                                          "krbtgt" +
                                          ullink.security.krb5.PrincipalName.NAME_COMPONENT_SEPARATOR +
                                          crealm.toString(),
                                          ullink.security.krb5.PrincipalName.KRB_NT_SRV_INST);
        } else
            req_sname = sname;

        ullink.security.krb5.internal.KerberosTime req_till = null;
        if (till == null) {
            req_till = new ullink.security.krb5.internal.KerberosTime();
        } else {
            req_till = till;
        }

        ullink.security.krb5.internal.KDCReqBody kdc_req_body = new ullink.security.krb5.internal.KDCReqBody(kdc_options,
                                                 cname,
                                                 crealm,
                                                 req_sname,
                                                 from,
                                                 req_till,
                                                 rtime,
                                                 Nonce.value(),
                                                 eTypes,
                                                 addresses,
                                                 null,
                                                 additionalTickets);

        return new ullink.security.krb5.internal.ASReq(
                         paData,
                         kdc_req_body);
    }

    ullink.security.krb5.internal.ASReq getMessage() {
        return asReqMessg;
    }
}
