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

import ullink.security.action.GetPropertyAction;
import ullink.security.krb5.internal.ccache.CredentialsCache;
import ullink.security.krb5.internal.crypto.EType;
import ullink.security.krb5.internal.ktab.KeyTab;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Date;

/**
 * This class encapsulates the concept of a Kerberos service
 * credential. That includes a Kerberos ticket and an associated
 * session key.
 */
public class Credentials {

    ullink.security.krb5.internal.Ticket ticket;
    ullink.security.krb5.PrincipalName client;
    ullink.security.krb5.PrincipalName server;
    ullink.security.krb5.EncryptionKey key;
    ullink.security.krb5.internal.TicketFlags flags;
    ullink.security.krb5.internal.KerberosTime authTime;
    ullink.security.krb5.internal.KerberosTime startTime;
    ullink.security.krb5.internal.KerberosTime endTime;
    ullink.security.krb5.internal.KerberosTime renewTill;
    ullink.security.krb5.internal.HostAddresses cAddr;
    ullink.security.krb5.EncryptionKey serviceKey;
    private static boolean DEBUG = ullink.security.krb5.internal.Krb5.DEBUG;
    private static CredentialsCache cache;
    static boolean alreadyLoaded = false;
    private static boolean alreadyTried = false;
    private static native Credentials acquireDefaultNativeCreds();

    public Credentials(ullink.security.krb5.internal.Ticket new_ticket,
                       ullink.security.krb5.PrincipalName new_client,
                       ullink.security.krb5.PrincipalName new_server,
                       ullink.security.krb5.EncryptionKey new_key,
                       ullink.security.krb5.internal.TicketFlags new_flags,
                       ullink.security.krb5.internal.KerberosTime authTime,
                       ullink.security.krb5.internal.KerberosTime new_startTime,
                       ullink.security.krb5.internal.KerberosTime new_endTime,
                       ullink.security.krb5.internal.KerberosTime renewTill,
                       ullink.security.krb5.internal.HostAddresses cAddr) {
        ticket = new_ticket;
        client = new_client;
        server = new_server;
        key = new_key;
        flags = new_flags;
        this.authTime = authTime;
        startTime = new_startTime;
        endTime = new_endTime;
        this.renewTill = renewTill;
        this.cAddr = cAddr;
    }

    public Credentials(byte[] encoding,
                       String client,
                       String server,
                       byte[] keyBytes,
                       int keyType,
                       boolean[] flags,
                       Date authTime,
                       Date startTime,
                       Date endTime,
                       Date renewTill,
                       InetAddress[] cAddrs) throws ullink.security.krb5.KrbException, IOException {
        this(new ullink.security.krb5.internal.Ticket(encoding),
             new ullink.security.krb5.PrincipalName(client, ullink.security.krb5.PrincipalName.KRB_NT_PRINCIPAL),
             new ullink.security.krb5.PrincipalName(server, ullink.security.krb5.PrincipalName.KRB_NT_SRV_INST),
             new ullink.security.krb5.EncryptionKey(keyType, keyBytes),
             (flags == null? null: new ullink.security.krb5.internal.TicketFlags(flags)),
             (authTime == null? null: new ullink.security.krb5.internal.KerberosTime(authTime)),
             (startTime == null? null: new ullink.security.krb5.internal.KerberosTime(startTime)),
             (endTime == null? null: new ullink.security.krb5.internal.KerberosTime(endTime)),
             (renewTill == null? null: new ullink.security.krb5.internal.KerberosTime(renewTill)),
             null); // caddrs are in the encoding at this point
    }

    /**
     * Acquires a service ticket for the specified service
     * principal. If the service ticket is not already available, it
     * obtains a new one from the KDC.
     */
    /*
    public Credentials(Credentials tgt, PrincipalName service)
        throws KrbException {
    }
    */

    public final ullink.security.krb5.PrincipalName getClient() {
        return client;
    }

    public final ullink.security.krb5.PrincipalName getServer() {
        return server;
    }

    public final ullink.security.krb5.EncryptionKey getSessionKey() {
        return key;
    }

    public final Date getAuthTime() {
        if (authTime != null) {
            return authTime.toDate();
        } else {
            return null;
        }
    }

    public final Date getStartTime() {
        if (startTime != null)
            {
                return startTime.toDate();
            }
        return null;
    }

    public final Date getEndTime() {
        if (endTime != null)
            {
                return endTime.toDate();
            }
        return null;
    }

    public final Date getRenewTill() {
        if (renewTill != null)
            {
                return renewTill.toDate();
            }
        return null;
    }

    public final boolean[] getFlags() {
        if (flags == null) // Can be in a KRB-CRED
        return null;
        return flags.toBooleanArray();
    }

    public final InetAddress[] getClientAddresses() {

        if (cAddr == null)
        return null;

        return cAddr.getInetAddresses();
    }

    public final byte[] getEncoded() {
        byte[] retVal = null;
        try {
            retVal = ticket.asn1Encode();
        } catch (Asn1Exception e) {
            if (DEBUG)
            System.out.println(e);
        } catch (IOException ioe) {
            if (DEBUG)
            System.out.println(ioe);
        }
        return retVal;
    }

    public boolean isForwardable() {
        return flags.get(ullink.security.krb5.internal.Krb5.TKT_OPTS_FORWARDABLE);
    }

    public boolean isRenewable() {
        return flags.get(ullink.security.krb5.internal.Krb5.TKT_OPTS_RENEWABLE);
    }

    public ullink.security.krb5.internal.Ticket getTicket() {
        return ticket;
    }

    public ullink.security.krb5.internal.TicketFlags getTicketFlags() {
        return flags;
    }

    /**
     * Checks if the service ticket returned by the KDC has the OK-AS-DELEGATE
     * flag set
     * @return true if OK-AS_DELEGATE flag is set, otherwise, return false.
     */
    public boolean checkDelegate() {
        return (flags.get(ullink.security.krb5.internal.Krb5.TKT_OPTS_DELEGATE));
    }

    public Credentials renew() throws ullink.security.krb5.KrbException, IOException {
        ullink.security.krb5.internal.KDCOptions options = new ullink.security.krb5.internal.KDCOptions();
        options.set(ullink.security.krb5.internal.KDCOptions.RENEW, true);
        /*
         * Added here to pass KrbKdcRep.check:73
         */
        options.set(ullink.security.krb5.internal.KDCOptions.RENEWABLE, true);

        return new ullink.security.krb5.KrbTgsReq(options,
                             this,
                             server,
                             null, // from
                             null, // till
                             null, // rtime
                             null, // eTypes
                             cAddr,
                             null,
                             null,
                             null).sendAndGetCreds();
    }

    /**
     * Returns a TGT for the given client principal from a ticket cache.
     *
     * @param princ the client principal. A value of null means that the
     * default principal name in the credentials cache will be used.
     * @param ticketCache the path to the tickets file. A value
     * of null will be accepted to indicate that the default
     * path should be searched
     * @returns the TGT credentials or null if none were found. If the tgt
     * expired, it is the responsibility of the caller to determine this.
     */
    public static Credentials acquireTGTFromCache(ullink.security.krb5.PrincipalName princ,
                                                  String ticketCache)
        throws ullink.security.krb5.KrbException, IOException {

        if (ticketCache == null) {
            // The default ticket cache on Windows is not a file.
            String os = java.security.AccessController.doPrivileged(
                        new GetPropertyAction("os.name"));
            if (os.toUpperCase().startsWith("WINDOWS")) {
                Credentials creds = acquireDefaultCreds();
                if (creds == null) {
                    if (DEBUG) {
                        System.out.println(">>> Found no TGT's in LSA");
                    }
                    return null;
                }
                if (princ != null) {
                    if (creds.getClient().equals(princ)) {
                        if (DEBUG) {
                            System.out.println(">>> Obtained TGT from LSA: "
                                               + creds);
                        }
                        return creds;
                    } else {
                        if (DEBUG) {
                            System.out.println(">>> LSA contains TGT for "
                                               + creds.getClient()
                                               + " not "
                                               + princ);
                        }
                        return null;
                    }
                } else {
                    if (DEBUG) {
                        System.out.println(">>> Obtained TGT from LSA: "
                                           + creds);
                    }
                    return creds;
                }
            }
        }

        /*
         * Returns the appropriate cache. If ticketCache is null, it is the
         * default cache otherwise it is the cache filename contained in it.
         */
        CredentialsCache ccache =
            CredentialsCache.getInstance(princ, ticketCache);

        if (ccache == null)
            return null;

        ullink.security.krb5.internal.ccache.Credentials tgtCred  =
            ccache.getDefaultCreds();

        if (EType.isSupported(tgtCred.getEType())) {
            return tgtCred.setKrbCreds();
        } else {
            if (DEBUG) {
                System.out.println(
                    ">>> unsupported key type found the default TGT: " +
                    tgtCred.getEType());
            }
            return null;
        }
    }

    /**
     * Returns a TGT for the given client principal via an AS-Exchange.
     * This method causes pre-authentication data to be sent in the
     * AS-REQ.
     *
     * @param princ the client principal. This value cannot be null.
     * @param secretKey the secret key of the client principal.This value
     * cannot be null.
     * @returns the TGT credentials
     */
    public static Credentials acquireTGT(ullink.security.krb5.PrincipalName princ,
                                         ullink.security.krb5.EncryptionKey[] secretKeys,
                                         char[] password)
        throws ullink.security.krb5.KrbException, IOException {

        if (princ == null)
            throw new IllegalArgumentException(
                        "Cannot have null principal to do AS-Exchange");

        if (secretKeys == null)
            throw new IllegalArgumentException(
                        "Cannot have null secretKey to do AS-Exchange");

        ullink.security.krb5.KrbAsRep asRep = null;
        try {
            asRep = sendASRequest(princ, secretKeys, null);
        } catch (ullink.security.krb5.KrbException ke) {
            if ((ke.returnCode() == ullink.security.krb5.internal.Krb5.KDC_ERR_PREAUTH_FAILED) ||
                (ke.returnCode() == ullink.security.krb5.internal.Krb5.KDC_ERR_PREAUTH_REQUIRED)) {
                // process pre-auth info
                if (DEBUG) {
                    System.out.println("AcquireTGT: PREAUTH FAILED/REQUIRED," +
                                " re-send AS-REQ");
                }

                ullink.security.krb5.internal.KRBError error = ke.getError();
                // update salt in PrincipalName
                byte[] newSalt = error.getSalt();
                if (newSalt != null && newSalt.length > 0) {
                    princ.setSalt(new String(newSalt));
                }

                // refresh keys
                if (password != null) {
                    secretKeys = ullink.security.krb5.EncryptionKey.acquireSecretKeys(password,
                            princ.getSalt(), true,
                            error.getEType(), error.getParams());
                }
                asRep = sendASRequest(princ, secretKeys, ke.getError());
            } else {
                throw ke;
            }
        }
        return asRep.getCreds();
    }

    /**
     * Sends the AS-REQ
     */
    private static ullink.security.krb5.KrbAsRep sendASRequest(ullink.security.krb5.PrincipalName princ,
        ullink.security.krb5.EncryptionKey[] secretKeys, ullink.security.krb5.internal.KRBError error)
        throws ullink.security.krb5.KrbException, IOException {

        // %%%
        ullink.security.krb5.KrbAsReq asReq = null;
        if (error == null) {
            asReq = new ullink.security.krb5.KrbAsReq(princ, secretKeys);
        } else {
            asReq = new ullink.security.krb5.KrbAsReq(princ, secretKeys, true,
                        error.getEType(), error.getSalt(), error.getParams());
        }

        String kdc = null;
        ullink.security.krb5.KrbAsRep asRep  = null;
        try {
            kdc = asReq.send();
            asRep =  asReq.getReply(secretKeys);
        } catch (ullink.security.krb5.KrbException ke) {
                if (ke.returnCode() == ullink.security.krb5.internal.Krb5.KRB_ERR_RESPONSE_TOO_BIG) {
                    asReq.send(princ.getRealmString(), kdc, true);
                    asRep =  asReq.getReply(secretKeys);
                } else {
                    throw ke;
                }
        }
        return asRep;
    }

    /**
     * Acquires default credentials.
     * <br>The possible locations for default credentials cache is searched in
     * the following order:
     * <ol>
     * <li> The directory and cache file name specified by "KRB5CCNAME" system.
     * property.
     * <li> The directory and cache file name specified by "KRB5CCNAME"
     * environment variable.
     * <li> A cache file named krb5cc_{user.name} at {user.home} directory.
     * </ol>
     * @return a <code>KrbCreds</code> object if the credential is found,
     * otherwise return null.
     */

    // this method is intentionally changed to not check if the caller's
    // principal name matches cache file's principal name.
    // It assumes that the GSS call has
    // the privilege to access the default cache file.

    public static synchronized Credentials acquireDefaultCreds() {
        Credentials result = null;

        if (cache == null) {
            cache = CredentialsCache.getInstance();
        }
        if (cache != null) {
            if (DEBUG) {
                System.out.println(">>> KrbCreds found the default ticket " +
                                   "granting ticket in credential cache.");
            }
            ullink.security.krb5.internal.ccache.Credentials temp =
                cache.getDefaultCreds();
            if (EType.isSupported(temp.getEType())) {
                result = temp.setKrbCreds();
            } else {
                if (DEBUG) {
                    System.out.println(
                        ">>> unsupported key type found the default TGT: " +
                        temp.getEType());
                }
            }
        }
        if (result == null) {
            // Doesn't seem to be a default cache on this system or
            // TGT has unsupported encryption type

            if (!alreadyTried) {
                // See if there's any native code to load
                try {
                    ensureLoaded();
                } catch (Exception e) {
                    if (DEBUG) {
                        System.out.println("Can not load credentials cache");
                        e.printStackTrace();
                    }
                    alreadyTried = true;
                }
            }
            if (alreadyLoaded) {
                // There is some native code
                if (DEBUG)
                   System.out.println(">> Acquire default native Credentials");
                result = acquireDefaultNativeCreds();
                // only TGT with DES key will be returned by native method
            }
        }
        return result;
    }


    /**
     * Gets service credential from key table. The credential is used to
     * decrypt the received client message
     * and authenticate the client by verifying the client's credential.
     *
     * @param serviceName the name of service, using format component@realm
     * @param keyTabFile the file of key table.
     * @return a <code>KrbCreds</code> object.
     */
    public static Credentials getServiceCreds(String serviceName,
                                              File keyTabFile) {
        ullink.security.krb5.EncryptionKey k = null;
        ullink.security.krb5.PrincipalName service = null;
        Credentials result = null;
        try {
            service = new ullink.security.krb5.PrincipalName(serviceName);
            if (service.getRealm() == null) {
                String realm = ullink.security.krb5.Config.getInstance().getDefaultRealm();
                if (realm == null) {
                    return null;
                } else {
                    service.setRealm(realm);
                }
            }
        } catch (ullink.security.krb5.RealmException e) {
            if (DEBUG) {
                e.printStackTrace();
            }
            return null;
        } catch (ullink.security.krb5.KrbException e) {
            if (DEBUG) {
                e.printStackTrace();
            }
            return null;
        }
        KeyTab kt;
        if (keyTabFile == null) {
            kt = KeyTab.getInstance();
        } else {
            kt = KeyTab.getInstance(keyTabFile);
        }
        if ((kt != null) && (kt.findServiceEntry(service))) {
            k = kt.readServiceKey(service);
            result = new Credentials(null, service, null, null, null,
                                     null, null, null, null, null);
            result.serviceKey = k;
        }
        return result;
    }



    /**
     * Acquires credentials for a specified service using initial credential.
     * When the service has a different realm
     * from the initial credential, we do cross-realm authentication
     * - first, we use the current credential to get
     * a cross-realm credential from the local KDC, then use that
     * cross-realm credential to request service credential
     * from the foreigh KDC.
     *
     * @param service the name of service principal using format
     * components@realm
     * @param ccreds client's initial credential.
     * @exception IOException if an error occurs in reading the credentials
     * cache
     * @exception ullink.security.krb5.KrbException if an error occurs specific to Kerberos
     * @return a <code>Credentials</code> object.
     */

    public static Credentials acquireServiceCreds(String service,
                                                  Credentials ccreds)
        throws ullink.security.krb5.KrbException, IOException {
        return ullink.security.krb5.internal.CredentialsUtil.acquireServiceCreds(service, ccreds);
    }


    /*
     * This method does the real job to request the service credential.
     */

    private static Credentials serviceCreds(ullink.security.krb5.ServiceName service,
                                            Credentials ccreds)
        throws ullink.security.krb5.KrbException, IOException {
        return new ullink.security.krb5.KrbTgsReq(
                new ullink.security.krb5.internal.KDCOptions(),
                ccreds,
                service,
                null, // KerberosTime from
                null, // KerberosTime till
                null, // KerberosTime rtime
                null, // int[] eTypes
                null, // HostAddresses addresses
                null, // AuthorizationData
                null, // Ticket[] additionalTickets
                null  // EncryptionKey subSessionKey
                ).sendAndGetCreds();
    }

    public CredentialsCache getCache() {
        return cache;
    }

    public ullink.security.krb5.EncryptionKey getServiceKey() {
        return serviceKey;
    }

    /*
     * Prints out debug info.
     */
    public static void printDebug(Credentials c) {
        System.out.println(">>> DEBUG: ----Credentials----");
        System.out.println("\tclient: " + c.client.toString());
        System.out.println("\tserver: " + c.server.toString());
        System.out.println("\tticket: realm: " + c.ticket.realm.toString());
        System.out.println("\t        sname: " + c.ticket.sname.toString());
        if (c.startTime != null) {
            System.out.println("\tstartTime: " + c.startTime.getTime());
        }
        System.out.println("\tendTime: " + c.endTime.getTime());
        System.out.println("        ----Credentials end----");
    }


    static void ensureLoaded() {
        java.security.AccessController.doPrivileged(
                new java.security.PrivilegedAction<Void> () {
                        public Void run() {
                                System.loadLibrary("w2k_lsa_auth");
                                return null;
                        }
                });
        alreadyLoaded = true;
    }

    public String toString() {
        StringBuffer buffer = new StringBuffer("Credentials:");
        buffer.append("\nclient=").append(client);
        buffer.append("\nserver=").append(server);
        if (authTime != null) {
            buffer.append("\nauthTime=").append(authTime);
        }
        if (startTime != null) {
            buffer.append("\nstartTime=").append(startTime);
        }
        buffer.append("\nendTime=").append(endTime);
        buffer.append("\nrenewTill=").append(renewTill);
        buffer.append("\nflags: ").append(flags);
        buffer.append("\nEType (int): ").append(key.getEType());
        return buffer.toString();
    }

}
