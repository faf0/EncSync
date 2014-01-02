EncSync
=======

About
-----

EncSync is an open-source network storage service that provides client-side
encryption and supports group file sharing. The service is based on the
client-server architecture.

An EncSync client encrypts files with a key that is unknown to the server before
it synchronizes the files with the server.
An EncSync server can be placed in a LAN, on the local machine in order to
obtain encrypted folder backups, in the cloud, and on any device that supports
Java. The client software is Java-based as well and therefore runs on any machine
that has Java installed. Just specify the folders on your client computers that
you want to synchronize with the server. You can also share folders with a group.
If possible, only file changes are transmitted to the server to reduce network
costs. The client is able to reconstruct the complete files based on the changes.

Features
--------

* Client-Side Encryption
* Encrypted Group File Sharing
* File Integrity Protection
* File Synchronization
* File Versioning
* Integration of Encryption and File Difference Modules
* Cross-Platform Compatibility

Non-Features
------------

* File-Name Encryption
* Random File Access
* Deduplication

Dependencies
------------

This project requires Java version 1.7 or higher and certain libraries which
are listed in `lib/README.md`.

How To Build
------------

Make sure that `JAVA_HOME` references a supported Java installation.
Build the client and the server using Apache Ant by running `ant` in the main directory
that contains `build.xml`. This will create the two JAR files
`build/jar/encsync-client.jar` and `build/jar/encsync-server.jar`.

Configuration
-------------

The communication channel between clients and the server is secured with TLS.
Furthermore, the client encrypts your files with a key that you specify before
it transmits your files to the server. In the following, we describe how to
configure the server and the client. Configuration files are written in JSON
syntax.

### Server

To generate an RSA key pair and a server certificate on the command line execute

    keytool -genkeypair -keystore SSLKeyStore -alias SSLCertificateWithRSA -keyalg RSA

Export the produced certificate with the command

    keytool -exportcert -alias SSLCertificateWithRSA -file .cert -keystore SSLKeyStore

Hand the certificate file `.cert` over to the clients. Clients need the
certificate to verify that they are communicating with the actual server and not
with a man in the middle.

Copy and modify one of the sample server configuration files under `files/server/`.
The parameter `max_failed_requests` is the maximum number of failed
authentication request messages that a client may send before the server blocks
the client. Client which reach that limit are banned from the server for
`block_timeout` milliseconds. The other parameters of the server configuration
should be self-explanatory.

### Client

Sample configuration files are present under `files/clients/*/.conf`.
Copy and adapt your configuration file of choice to suit your needs.
The parameter `diff_threshold` determines when diffs rather than complete files
are to be uploaded. The threshold size is the value of diff threshold multiplied
by the file size of the target. If the size of the diff does not exceed the
threshold size, the client will upload the diff rather than the complete file.
The parameter `sync_interval` reflects the periodic synchronization interval in
seconds. The remaining parameters of the client configuration should be
self-explanatory.

In order to register a user on the server, launch the server and run
`client.tools.PutAuthShell` by executing the following command:

    ant register-user -Darg0=mydir/.myconf

You may synchronize files contained in a folder which we call the private
folder or working directory. The private folder must contain a special file
named `.access` that contains the keys and encryption algorithms which will
be used to encrypt the files on the client-side. We call these files access bundles.
There are two types of access bundles: the private access bundle which is located
directly in the private folder and group access bundles that may be placed
in first-level subfolders of the private folder. You share files by placing
a group access bundle with the name `.access` in the desired folder.
If a file that is contained in the private folder on any level is not
explicitly shared, i.e., if there is no corresponding group access bundle,
the client will encrypt the file as specified in the private access bundle.

Create a private access bundle using `client.tools.AccessBundleShell` and
place it inside your configured private folder located at `root_path`. Run
the following command to create an access bundle:

    ant access-bundle

To share a folder, register the shared folder using `client.tools.PutFolderShell`.
Execute the following command in a shell:

    ant put-folder -Darg0=mydir/.myconf

The server needs to be running during this process.
Create a group access bundle with the command given above and place it under
a sub-folder of your `root_path`.

Keys can be renewed by creating new keys and incrementing the `minimum_key` in the
access bundle.
Using the put-folder tool, the `minimum_key` entry can be updated on the server.

Encryption can be turned off for shared folders by leaving out both the content
and integrity key arrays in the group access bundle. However, files in the
private folder or in subfolders that do not have an access bundle are always
encrypted with the newest content key from the private access bundle.

If you want to prevent the client from synchronizing any files, create a file
called `.lock` and place it in your private folder. You may decide to do this,
for example, when you are about to edit some files. You can also place `.lock`
files in shared folders to only lock the corresponding files.

How To Run
----------

### Server

To start a client instance, run:

    java -jar encsync-client.jar -Darg0=mydir/.myconf

### Client

To start a server instance, run:

    java -jar encsync-server.jar -Darg0=mydir/.myconf

Recovery
--------

System crashes may lead to an inconsistent state on the client or server.
Run the following tools to recover from a crash.

### Server

    ant recover-server -Darg0=mydir/.myconf

### Client

    ant recover-client -Darg0=mydir/.myconf

More Information
----------------

This software was designed and implemented as part of my work for my [master thesis].
Check out my thesis for details on the original design of this software.
Note that, as of now, EncSync is a proof-of-concept and under development.
It needs more testing before it is ready for production use.

Contact
-------

For bug reports create an [issue] on GitHub.

Copyright
---------

Copyright 2013 Fabian Foerg

Licensed under the GPLv3.
See file COPYING or
[http://www.gnu.org/licenses/gpl-3.0.html](http://www.gnu.org/licenses/gpl-3.0.html).

The files src/misc/JSONPrettyPrintWriter.java and src/test/JsonWriterTest.java
were originally created by Elad Tabak and are released under the
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).

  [master thesis]: http://www.ffoerg.de/doc/foerg_fabian_master_thesis.pdf
  [issue]: https://github.com/faf0/EncSync/issues

