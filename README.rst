============
swugenerator
============

A host tool to generate SWU update package for SWUpdate.


SYNOPSIS
========

usage: SWUGenerator [-h] [-K ENCRYPTION_KEY_FILE] [-k SIGN] [-s SW_DESCRIPTION]
                    [-a ARTIFACTORY] -o SWU_FILE [-c CONFIG]
                    command

Generator SWU Packages for SWUpdate

positional arguments:
  command:
    {create,sign,mender}  command to be executed
      create              creates a SWU file
      sign                signs an existing SWU file provided by -i
      mender              wraps an existing SWU file provided by -i into a Mender Artifact

optional arguments:
  -h, --help            show this help message and exit
  -K ENCRYPTION_KEY_FILE, --encryption-key-file ENCRYPTION_KEY_FILE
                        AES Key to encrypt artifacts
  -n, --no-compress     Do not compress files
  -e, --no-encrypt      Do not encrypt files, for artifacts that are already encrypted.
                        encrypted and ivt are kept as set in sw-description
  -x, --no-ivt          Do not generate IV when encrypting
  -y, --no-hash         Do not store sha256 hash in sw-description
  -k SIGN, --sign SIGN  RSA key or certificate to sign the SWU
  -s SW_DESCRIPTION, --sw-description SW_DESCRIPTION
                        sw-description template for the create command
  -t, --encrypt-swdesc  Encrypt sw-description
  -a ARTIFACTORY, --artifactory ARTIFACTORY
                        list of directories where artifacts are searched
  -o SWU_FILE, --swu-file SWU_FILE
                        SWU output file
  -i, --swu-in-file SWU_IN_FILE
                        SWU input file to be signed for the sign command
  -c CONFIG, --config CONFIG
                        configuration file


Description
===========

``swugenerator`` is a tool running on host to create and modify SWUpdate's Update
files (SWU). SWU file contains a meta description of the release (``sw-description``),
and swugenerator adds components to a template passed from command line.
This tool requires *openssl* to run and to sign the SWU. It is goal of the tool to fill
the gap with Yocto/OE, where SWU generation is done by classes in the meta-swupdate layer,
but other buildsystems like Debian or Buildroot have no tools to create a SWU.

The tool signs the SWU and can encrypt the artifacts. The tool parses the libconf based sw-description (tool does not work for JSON based sw-description) and provides the following features:

        - replace occurrencies of variables found in the CONFIG file
        - add sha256 to each artifact
        - check if an artifact should be encrypted and encrypts it
        - sign sw-description with one of the methods accepted by SWUpdate
        - pack all artifacts into a SWU file

It maybe run in two steps to create an unsigned swu file and then sign it later in a second call::

    swugenerator -o output.swu -a . -s sw-description.in create
    swugenerator -o signed_output.swu -i output.swu -k CMS,key.pem,ca.crt sign

Mender Artifact
---------------

A Mender Server delivers updates only as Mender Artifacts. The ``mender`` command puts
an existing SWU, unchanged and with its signature, into a Mender Artifact (format
version 3) as the payload of type ``swu``, as
``mender-artifact write module-image -T swu`` does. SWUpdate's Mender Suricatta module
takes the SWU out of the artifact while it is downloaded::

    swugenerator -o update.mender mender -i signed_output.swu -D board-a -D board-b -N release-2

Options of the ``mender`` command::

  -i, --swu-in-file SWU_IN_FILE
                        SWU to wrap
  -D, --device-type DEVICE_TYPE
                        compatible device type, can be repeated
  -N, --artifact-name ARTIFACT_NAME
                        artifact name, default: version in sw-description
  -T, --payload-type PAYLOAD_TYPE
                        payload type, default: swu
  -C, --compression {gzip,xz,none}
                        compression of header and payload, default: gzip

The artifact is reproducible with ``SOURCE_DATE_EPOCH``.


Installation
============

To install ``swugenerator`` clone the repository, and from the main project folder run pip (pip3 required):
For new Linux distributions, replace it with `pipx`.

::

    pip install .

To uninstall: ::

    pip uninstall swugenerator
