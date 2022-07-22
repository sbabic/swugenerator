============
swugenerator
============

A host tool to generate SWU update package for SWUpdate.


SYNOPSIS
========

usage: SWUGenerator [-h] [-K ENCRYPTION_KEY_FILE] [-k SIGN] -s SW_DESCRIPTION
                    [-a ARTIFACTORY] -o SWU_FILE [-c CONFIG]
                    command

Generator SWU Packages for SWUpdate

positional arguments:
  command               command to be executed, one of : create

optional arguments:
  -h, --help            show this help message and exit
  -K ENCRYPTION_KEY_FILE, --encryption-key-file ENCRYPTION_KEY_FILE
                        AES Key to encrypt artifacts
  -k SIGN, --sign SIGN  RSA key or certificate to sign the SWU
  -s SW_DESCRIPTION, --sw-description SW_DESCRIPTION
                        sw-description template
  -t, --encrypt-swdesc  Encrypt sw-description
  -a ARTIFACTORY, --artifactory ARTIFACTORY
                        list of directories where artifacts are searched
  -o SWU_FILE, --swu-file SWU_FILE
                        SWU output file
  -c CONFIG, --config CONFIG
                        configuration file


Description
===========

`swugenerator` is a tool running on host to create and modify SWUpdate's Update
files (SWU). SWU file contains a meta description of the release (`sw-description`), 
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
