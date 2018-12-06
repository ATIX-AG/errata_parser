# Errata-Parser v2.0

## Development

Run the following script to add a git hook, which will automatically validate your code

    scripts/bootstrap.sh

## Source of information

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

Right now the errata are presented as YAML, but changing that to JSON is trivial.
The structure is always the same.

#### YAML:

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

## Implementation

1. Pull Security-Information
1. Gather information per CVE/DSA/USN or similar:
   1. General information (e.g. description)
   1. Affected Packages
   1. Affected Package-binary-versions (may have to be looked-up in packages-directory; e.g. packages.debian.org)
   1. TODO Affected release!?
1. Save data in local database (optional) or sort data into database while parsing the information-source.
1. Create our own Errata-JSON/YAML/... to be downloaded by orcharhino-installations OR (better) provide REST-API to download specific Errata (for certain release/packages or new errata since specified date)


## Usage

### Initialize

    bundle install

### Generate Errata

#### Debian:

For Debian, the packages-data must be fetched from the repository first.

    bundle exec debRelease.rb > packages_everything.json
    bundle exec gen_errata.rb debian > errata_debian.yaml

#### Ubuntu:

    bundle exec gen_errata.rb ubuntu > errata_ubuntu.yaml


### Testing

    bundle exec ruby test/gen_errata.rb

#### Re-Record Errata for test

    bundle exec gen_errata.rb debian_test_record > test/data/debian.yaml
    bundle exec gen_errata.rb ubuntu_test_record > test/data/ubuntu.yaml

### Docker container

#### Create from local files:

    docker build -r errata_parser:latest .

#### Testing:

    docker run --rm errata_parser:latest bundle exec ruby test/gen_errata.rb

#### Running:

    docker run --rm --mount type=bind,source="${pwd}/errata",target=/errata --mount source=errataparser_temp,target=/tmp/errataparser -ti errata_parser:latest

Make sure to create a `config.json` in `${pwd}/errata`-directory before running
