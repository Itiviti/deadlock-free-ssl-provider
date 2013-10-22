/*
 * Copyright (c) 2000, 2012, Oracle and/or its affiliates. All rights reserved.
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

package ullink.security.provider.certpath;

import ullink.security.util.Debug;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.util.*;

/**
 * A specification of a forward PKIX validation state
 * which is initialized by each build and updated each time a
 * certificate is added to the current path.
 * @since       1.4
 * @author      Yassir Elley
 */
class ForwardState implements State {

    private static final Debug debug = Debug.getInstance("certpath");

    /* The issuer DN of the last cert in the path */
    X500Principal issuerDN;

    /* The last cert in the path */
    ullink.security.x509.X509CertImpl cert;

    /* The set of subjectDNs and subjectAltNames of all certs in the path */
    HashSet<ullink.security.x509.GeneralNameInterface> subjectNamesTraversed;

    /*
     * The number of intermediate CA certs which have been traversed so
     * far in the path
     */
    int traversedCACerts;

    /* Flag indicating if state is initial (path is just starting) */
    private boolean init = true;

    /* the checker used for revocation status */
    public ullink.security.provider.certpath.CrlRevocationChecker crlChecker;
    
    /* the untrusted certificates checker */
    ullink.security.provider.certpath.UntrustedChecker untrustedChecker;

    /* The list of user-defined checkers that support forward checking */
    ArrayList<PKIXCertPathChecker> forwardCheckers;

    /* Flag indicating if key needing to inherit key parameters has been
     * encountered.
     */
    boolean keyParamsNeededFlag = false;

    /**
     * Returns a boolean flag indicating if the state is initial
     * (just starting)
     *
     * @return boolean flag indicating if the state is initial (just starting)
     */
    public boolean isInitial() {
        return init;
    }

    /**
     * Return boolean flag indicating whether a public key that needs to inherit
     * key parameters has been encountered.
     *
     * @return boolean true if key needing to inherit parameters has been
     * encountered; false otherwise.
     */
    public boolean keyParamsNeeded() {
        return keyParamsNeededFlag;
    }

    /**
     * Display state for debugging purposes
     */
    public String toString() {
        StringBuffer sb = new StringBuffer();
        try {
            sb.append("State [");
            sb.append("\n  issuerDN of last cert: " + issuerDN);
            sb.append("\n  traversedCACerts: " + traversedCACerts);
            sb.append("\n  init: " + String.valueOf(init));
            sb.append("\n  keyParamsNeeded: "
                + String.valueOf(keyParamsNeededFlag));
            sb.append("\n  subjectNamesTraversed: \n" + subjectNamesTraversed);
            sb.append("]\n");
        } catch (Exception e) {
            if (debug != null) {
                debug.println("ForwardState.toString() unexpected exception");
                e.printStackTrace();
            }
        }
        return sb.toString();
    }

    /**
     * Initialize the state.
     *
     * @param certPathCheckers the list of user-defined PKIXCertPathCheckers
     */
    public void initState(List<PKIXCertPathChecker> certPathCheckers)
        throws CertPathValidatorException
    {
        subjectNamesTraversed = new HashSet<ullink.security.x509.GeneralNameInterface>();
        traversedCACerts = 0;

        /*
         * Populate forwardCheckers with every user-defined checker
         * that supports forward checking and initialize the forwardCheckers
         */
        forwardCheckers = new ArrayList<PKIXCertPathChecker>();
        if (certPathCheckers != null) {
            for (PKIXCertPathChecker checker : certPathCheckers) {
                if (checker.isForwardCheckingSupported()) {
                    checker.init(true);
                    forwardCheckers.add(checker);
                }
            }
        }

        init = true;
    }

    /**
     * Update the state with the next certificate added to the path.
     *
     * @param cert the certificate which is used to update the state
     */
    public void updateState(X509Certificate cert)
        throws CertificateException, IOException, CertPathValidatorException {

        if (cert == null)
            return;

        ullink.security.x509.X509CertImpl icert = ullink.security.x509.X509CertImpl.toImpl(cert);

        /* see if certificate key has null parameters */
        PublicKey newKey = icert.getPublicKey();
        if (newKey instanceof DSAPublicKey &&
            ((DSAPublicKey)newKey).getParams() == null) {
            keyParamsNeededFlag = true;
        }

        /* update certificate */
        this.cert = icert;

        /* update issuer DN */
        issuerDN = cert.getIssuerX500Principal();

        if (!ullink.security.x509.X509CertImpl.isSelfIssued(cert)) {

            /*
             * update traversedCACerts only if this is a non-self-issued
             * intermediate CA cert
             */
            if (!init && cert.getBasicConstraints() != -1) {
                traversedCACerts++;
            }
        }

        /* update subjectNamesTraversed only if this is the EE cert or if
           this cert is not self-issued */
        if (init || !ullink.security.x509.X509CertImpl.isSelfIssued(cert)){
            X500Principal subjName = cert.getSubjectX500Principal();
            subjectNamesTraversed.add(ullink.security.x509.X500Name.asX500Name(subjName));

            try {
                ullink.security.x509.SubjectAlternativeNameExtension subjAltNameExt
                    = icert.getSubjectAlternativeNameExtension();
                if (subjAltNameExt != null) {
                    ullink.security.x509.GeneralNames gNames = (ullink.security.x509.GeneralNames)
                        subjAltNameExt.get(ullink.security.x509.SubjectAlternativeNameExtension.SUBJECT_NAME);
                    for (Iterator<ullink.security.x509.GeneralName> t = gNames.iterator();
                                t.hasNext(); ) {
                        ullink.security.x509.GeneralNameInterface gName = t.next().getName();
                        subjectNamesTraversed.add(gName);
                    }
                }
            } catch (Exception e) {
                if (debug != null) {
                    debug.println("ForwardState.updateState() unexpected "
                        + "exception");
                    e.printStackTrace();
                }
                throw new CertPathValidatorException(e);
            }
        }

        init = false;
    }

    /*
     * Clone current state. The state is cloned as each cert is
     * added to the path. This is necessary if backtracking occurs,
     * and a prior state needs to be restored.
     *
     * Note that this is a SMART clone. Not all fields are fully copied,
     * because some of them will
     * not have their contents modified by subsequent calls to updateState.
     */
    public Object clone() {
        try {
            ForwardState clonedState = (ForwardState) super.clone();

            /* clone checkers, if cloneable */
            clonedState.forwardCheckers = (ArrayList<PKIXCertPathChecker>)
                                                forwardCheckers.clone();
            ListIterator<PKIXCertPathChecker> li =
                                clonedState.forwardCheckers.listIterator();
            while (li.hasNext()) {
                PKIXCertPathChecker checker = li.next();
                if (checker instanceof Cloneable) {
                    li.set((PKIXCertPathChecker)checker.clone());
                }
            }

            /*
             * Shallow copy traversed names. There is no need to
             * deep copy contents, since the elements of the Set
             * are never modified by subsequent calls to updateState().
             */
            clonedState.subjectNamesTraversed
                = (HashSet<ullink.security.x509.GeneralNameInterface>)subjectNamesTraversed.clone();
            return clonedState;
        } catch (CloneNotSupportedException e) {
            throw new InternalError(e.toString());
        }
    }
}
