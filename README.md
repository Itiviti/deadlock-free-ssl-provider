deadlock-free-ssl-provider
==========================

a ssl provider extracted from OpenJDK6-b27 


This ssl provider is aimed to solve the deadlock problem of SSLSocket impletation in Oracle JDK6. 

In Oracle JDK 6u45, or in the lastest implementation of OpenJDK7, a deadlock can happen when two threads access SSLSocketImpl.readRecord() and SSLSocketImpl.isClosed() at the same time by requiring 'this' lock and 'writeLock' lock in an inverse order.

In OpenJDK6-b27 implementation doesn't lock 'writeLock' in SSLSocketImpl, so there will be no this specific deadlock. 

This project extracts the implementation of SSL layer of OpenJDK6-b27, package as SSL provider according to Java Cryptography Architecture. 



