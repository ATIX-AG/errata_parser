# Errata-Parser v2.0 

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

### ...


## Errata Format
*TODO*

## Implementation

1. Pull Security-Information
1. Gather information per CVE/DSA/USN or similar:
   1. General information (e.g. description)
   1. Affected Packages
   1. Affected Package-binary-versions (may have to be looked-up in packages-directory; e.g. packages.debian.org)
   1. TODO Affected release!?
1. Save data in local database (optional) or sort data into database while parsing the information-source.
1. Create our own Errata-JSON/YAML/... to be downloaded by orcharhino-installations OR (better) provide REST-API to download specific Errata (for certain release/packages or new errata since specified date)

---
[^ubuntujsonformat]: see <https://blueprints.launchpad.net/ubuntu/+spec/security-p-usn-database-format>
