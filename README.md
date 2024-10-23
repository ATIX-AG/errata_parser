This Debian/Ubuntu `errata_parser` can use the "Debian Security Announcements (DSA)" and "Ubuntu Security Notices (USN)" to generate YAML files containing up to date Debian or Ubuntu erratum information.

It is designed to be used in conjunction with the accompanying `errata_server` project (https://github.com/ATIX-AG/errata_server), to provide a Debian/Ubuntu errata service.
This errata service is ultimately intended for use with Katello (https://github.com/Katello/katello).
However, at the time of writing the needed changes to Katello have not yet been merged.


# Quick Start Guide

This quick start guide covers the basic installation and usage of this repository for a typical developer use case.

There also is a puppet-module for installing the errata-parser and -server: https://github.com/chrisongthb/puppet-errata_parser


## Installation/First Time Setup

The first time installation steps only need to be performed once after checking out this repository.

### Install Package Dependencies

To use this repository you will need to install several packages.
On Debian they include:

    ruby (tested with version 2.5)
    bundler
    libapt-pkg-dev

If you want to build the Docker image provided by this repository, you will also need a working Docker installation (https://docs.docker.com/install/).

Note: If you notice additional dependencies when using this repository, please let us know so we can improve this `README.md` file.
Do feel free to open a pull request!


### Install Ruby Dependencies

Use `bundle install` in the repository root to install the needed ruby dependencies:

    bundle install --path vendor/bundle

Using `--path vendor/bundle` will ensure that all ruby dependencies are installed within the `vendor` folder, which is included in this repositories `.gitignore` file.
This is generally preferrable than installing to the system RubyGems!


### Enabling Syntax Checking

You can add a git hook that enables syntax checking using rubocop before committing, by running the following script:

    scripts/bootstrap.sh


## Local Usage

The `gen_errata.rb` script is mainly intended for local usage during development.
Only the Docker container (explained below) is intended for production use.


### Ubuntu Errata

You can generate Ubuntu errata information by running the `gen_errata.rb` script as follows:

    bundle exec debRelease.rb ubuntu > packages_everything.json
    bundle exec gen_errata.rb ubuntu > errata_ubuntu.yaml

The `packages_everything.json` file from the first of these two commands stores package information from the Ubuntu security repository (http://security.ubuntu.com/ubuntu)
This is needed to make sure to only handle referenced packages which are provided by repository.

Note that the `ubuntu` argument of the `gen_errata.rb` script is hard coded to use https://usn.ubuntu.com/usn-db/database.json.bz2 as its source of information, and to generate errata for `bionic` for `amd64` only.


### Debian Errata

You can generate Debian errata information by running the `gen_errata.rb` script as follows:

    bundle exec debRelease.rb debian > packages_everything.json
    bundle exec gen_errata.rb debian > errata_debian.yaml

The `packages_everything.json` file from the first of these two commands stores package information from the Debian security repository (http://security.debian.org/debian-security)
This is needed to map the source packages referenced in the Debian Security Announcements to the binary packages listed in the final `errata_debian.yaml` file.

Note that the `debian` argument of the `gen_errata.rb` script is hard coded to use https://salsa.debian.org/security-tracker-team/security-tracker/raw/master/data/DSA/list and https://security-tracker.debian.org/tracker/data/json as its source of information, and to generate errata for `stretch` for `amd64` only.


## Testing

To run the tests for this repository use:

    bundle exec ruby test/all.rb

If you make changes to this repository, it may become necessary to re-record the test data:

    bundle exec gen_errata.rb debian_test_record > test/data/debian.yaml
    bundle exec gen_errata.rb ubuntu_test_record > test/data/ubuntu.yaml

Note that pull requests will only be accepted once all tests run both within and outside of the container.


## Docker Container

The errata parser provided by this repository is intended for use within a Docker container.

To build the relevant container image use:

    docker build -t errata_parser:latest .

Note that the image build uses a `.dockerignore` whitelist to ensure only those files we really need are sent to the build context.
If you want to add aditional files to the container image, you will need to add them to the whitelist.

Once built, you can run the tests within the container as follows:

    docker run --rm errata_parser:latest bundle exec ruby test/all.rb

If you want to run the container interactively to see what the world looks like from within it, you can use:

    docker run --rm -it --entrypoint=/bin/bash errata_parser:latest

We recommend using the following set of commands for a feature run of the errata parser:

    docker volume create errata
    docker volume create errata_parser_temp
    docker run --rm \
      --mount type=volume,source=errata,target=/errata \
      --mount type=volume,source=errata_parser_temp,target=/tmp/errata_parser \
      errata_parser:latest

A so defined feature run will use the errata parsers default configuration, as defined by the `default_config.json` file.
(Within the container this file is located at `/etc/errata_parser.json`.)

To supply an individual container run with an alternate configuration add the following option to the `docker run` command:

    --mount type=bind,source=<absolute_path_to_user_config>,target=/etc/errata_parser.json

Also see the "Configuration" section under "Advanced Topics" below.

The container will run as configured, and place any output in the `errata` volume.
This volume also serves as the interface to the `errata_server` project.
The container's output files use JSON format, since the `errata_server` wants JSON.
In addition to the errata lists themselves, the container will also generate a configuration file for each errata list.
These configuration files will tell the `errata_server` what releases, components, and architectures each errata list contains.

A successfull run of the errata parser container, using the default configuration found in the `default_config.json` file from this repository, will result in the following new files:

    debian_config.json
    debian_errata.json
    ubuntu_config.json
    ubuntu_errata.json


# Advanced Topics

This section of the readme provides some additional background information, for those who want to delve deeper.


## Possible Sources of Information

This section collects various links were Debian and Ubuntu security information is published.
Not all of these are in use (and have been tested) with the default configuration of this errata parser.


### Debian

* Debian Security Tracker (derived from DSAs):
  * <https://security-tracker.debian.org/tracker/>
* List of DSAs from the website-source-code
  * <https://salsa.debian.org/security-tracker-team/security-tracker/blob/master/data/DSA/list>
* JSON-file including all information from Debian Security Tracker (sorted by package-name, CVE-number, release-name)
  * <https://security-tracker.debian.org/tracker/data/json>


### Ubuntu

1. Ubuntu Security Notices (USN)
   * <https://usn.ubuntu.com/>
1. JSON-file[^ubuntujsonformat] including all information from Ubuntu Security Notifications (sorted by USN-number, release); includes binary-versions
   * <https://usn.ubuntu.com/usn-db/database.json> (<https://usn.ubuntu.com/usn-db/database.json.sha256>)
   * <https://usn.ubuntu.com/usn-db/database-all.json> (<https://usn.ubuntu.com/usn-db/database-all.json.sha256>)
   * <https://usn.ubuntu.com/usn-db/database.json.bz2> (<https://usn.ubuntu.com/usn-db/database.json.bz2.sha256>)
   * <https://usn.ubuntu.com/usn-db/database-all.json.bz2> (<https://usn.ubuntu.com/usn-db/database-all.json.bz2.sha256>)

---
[^ubuntujsonformat]: see <https://blueprints.launchpad.net/ubuntu/+spec/security-p-usn-database-format>


## Errata Format

When used locally the errata parser produces output in YAML format.
However, the errata parser container produces structurally the same output in JSON instead.
The reason is that the `errata_server` companion project requires JSON for input.

See the following example for the structure of an individual erratum entry (in YAML):

    - name: DSA-4283-1
      title: ruby-json-jwt -- security update
      issued: "31 Aug 2018"
      affected_source_package: ruby-json-jwt
      packages:
      - name: ruby-json-jwt
        version: 1.6.2-1+deb9u1
        architecture: all
        component: main
        release: stretch
      description: 'Nov json-jwt version >= 0.5.0 && < 1.9.4 contains a CWE-347: Improper
        Verification of Cryptographic Signature vulnerability in Decryption of AES-GCM
        encrypted JSON Web Tokens that can result in Attacker can forge a authentication
        tag. This attack appear to be exploitable via network connectivity. This vulnerability
        appears to have been fixed in 1.9.4 and later.'
      cves:
      - CVE-2018-1000539
      severity: medium
      scope: remote
      dbts_bugs:
      - 902721


## Configuration

As previously mentioned, container runs can (and must) be configured via a configuration file named `config.json` present in the `/errata/` folder within the container.
As the `.json` extension suggests, the configuration file must contain a specific JSON data structure.

The default configuration is given by the `default_config.json` file within this repository which is also used for testing.

The top level data structure within the configuration file may contain the following fields:

    {
      "tempdir": "tmp/errata_parser",
      "debian": <debian_dict>,
      "ubuntu": <ubuntu_dict>
    }

The `tempdir` field gives the location to which the errata parser will download the upstream sources of information.
In the usage examples within this README, we mount an external folder to this location within the container.
This can improve performance, since the errata parser will NOT re-download these files if there is no newer version available on the upstream server than has already been downloaded.

The `debian` and `ubuntu` fields must be given if errata are to be generate for the respective operating systems.

The `<debian_dict>` must contain the following fields:

    "debian": {
      "dsa_list_url": <url>,
      "cve_list_url": <url>,
      "repositories": [ <repository_dict>, ... ]
      "whitelists": <whitelists_dict>,
      "aliases": <aliases_dict>
    }

Note that for debian, we require three upstream sources of information to generate errata:
The `dsa.list` file obtained via the `dsa_list_url` associates CVEs with debian binary packages.
The `cve.json` obtained via `cve_list_url` contains the actual information associated with these CVEs.
The `repository_dict` must be a dict containing a `repo_url`-string defining a debian-security repositories URL (up to the path containing the `dists`-directory as well as an `releases` array of strings defining the releases, containing the relevant binary packages.

The `whitelists` field allows users to filter the Debian repositories for which errata should be generated by "releases", "components", and "architectures".
An example:

    whitelists: {
      "releases": ["stretch"],
      "components": ["main", "contrib"],
      "architectures": ["amd64", "armhf"]
    }

If no components (or architectures) are given, this is interpreted as "all components (or architectures)".

The `aliases` field is needed since the accompanying `errata_server` must be able to associate Debian security repositories like `stretch/updates` with errata for Debian `stretch`.

The `<ubuntu_dict>` is somewhat simpler than that for Debian:

    "ubuntu": {
      "usn_list_url": <url>,
      "whitelists": <whitelists_dict>,
      "aliases": <aliases_dict>
    }

A single USN URL will suffice as an upstream source of information.
`whitelists` and `aliases` are structurally identical to those for Debian.


## Analyze created JSON files

To have an idea about how many errata and also how many packages per errata on avarage were created the following tool can be used:

    bundle exec analyzer.rb <errata-json>

It is also possible now to check if the latest security-notices that can be found on the RSS-feeds are already part of the errata-file.
The `check_latest_errata.rb` command returns a nagios-compliant output and return-code.

This requires the `monitor` gem-group to be installed by bundler

    bundle config set with 'monitor'
    bundle
