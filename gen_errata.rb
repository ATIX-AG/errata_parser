#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'yaml'
require 'time'
require 'debian'
require 'pathname'

require_relative 'parse_dsalist'
require_relative 'downloader'

URGENCY_PRIO = [
  'not yet assigned',
  'unimportant',
  'low',
  'medium',
  'high'
].freeze
SCOPE_PRIO = [
  'local',
  'remote'
].freeze

# Parser exceptions
class ParserException < RuntimeError
  def at
    str = ''
    str += @id unless @id.nil?
    str += ":#{@rel}" unless @rel.nil?
    str += ":#{@pkg}" unless @pkg.nil?
    str
  end

  def initialize(message, id=nil, release=nil, package=nil)
    @id = id
    @rel = release
    @pkg = package

    super("InvalidData(#{at}): #{message}")
  end
end

# The erratum main class
class Erratum
  attr_accessor :title, :name, :cves, :source_package, :fixed_version, :dbts_bugs
  attr_writer :description

  def initialize
    @cves = []
    @packages = []
    @dbts_bugs = []
    @severity_idx = -1
    @scope_idx = -1
  end

  def issued=(date)
    @issued = Time.parse date if date.is_a? String
    @issued = Time.at date if date.is_a? Numeric
    @issued = date if date.is_a? Time
  end

  def issued
    @issued.utc.strftime('%d %b %Y')
  end

  def description
    description = ''
    @description.each_line do |line|
      description += line.gsub(/(.{1,90})(\s+|\Z)/, "\\1\n")
    end
    description
  end

  def add_cve(cve)
    raise "Invalid CVE number #{cve}" unless cve =~ /CVE-\d{4,}-\d+/

    @cves << cve
  end

  def add_package(name, version, architecture: nil, release: nil, component: nil)
    hsh = {
      name: name,
      version: version,
      architecture: architecture,
      release: release,
      component: component
    }
    @packages << hsh unless @packages.include? hsh
  end

  def replace_packages
    new_data = []
    @packages.each do |p|
      new_data_p = yield p
      if new_data_p.nil?
        new_data << p
      elsif new_data_p.is_a?(Hash)
        new_data << new_data_p
      elsif new_data_p.is_a?(Array)
        new_data.concat new_data_p
      else
        raise "Invalid return-type #{new_data_p.class.name}"
      end
    end
    @packages = new_data
  end

  def packages
    res = []
    @packages.each do |p|
      new = {
        'name' => p[:name],
        'version' => p[:version]
      }
      # only add these values if set
      new['architecture'] = p[:architecture] if p[:architecture]
      new['component'] = p[:component] if p[:component]
      new['release'] = p[:release] if p[:release]
      res << new
    end
    res
  end

  def severity=(severity)
    @severity_idx = priorized_value(@severity_idx, severity, URGENCY_PRIO, 'Severity')
  end

  def severity
    URGENCY_PRIO[@severity_idx] unless @severity_idx == -1
  end

  def scope=(scope)
    @scope_idx = priorized_value(@scope_idx, scope, SCOPE_PRIO, 'scope')
  end

  def scope
    SCOPE_PRIO[@scope_idx] unless @scope_idx == -1
  end

  def add_debian_bug(dbts)
    @dbts_bugs << dbts
  end

  def to_h
    hsh = {
      'name' => name,
      'title' => title,
      'issued' => issued,
      'affected_source_package' => source_package,
      'packages' => packages,
      'description' => description
    }
    hsh['cves'] = cves.clone
    hsh['severity'] = severity if severity
    hsh['scope'] = scope if scope
    hsh['dbts_bugs'] = @dbts_bugs unless @dbts_bugs.nil? || @dbts_bugs.empty?
    hsh
  end

  def to_yaml
    to_h.clone.to_yaml
  end

  def to_json(options = {})
    to_h.to_json(options)
  end

  private

  ### Helper
  # TODO too static, what if a new value is introduced?
  # returns index of new in list, if the new is greater than old_idx
  # otherwise it returns the old_idx
  # Parameters:
  #   old_idx: Integer old index
  #   new:     String (or whatever element-type list has)
  #   list:    Array of possible values
  #   name:    convenient name for the value (for Exceptions)
  def priorized_value(old_idx, new, list, name='value')
    # skip if it was empty
    return old_idx if new.nil? || new.empty?

    new_idx = list.index new
    raise "UNKNOWN #{name} #{new.inspect} should be one of #{list.inspect}" if new_idx.nil?

    return new_idx if old_idx.nil? || new_idx > old_idx

    old_idx
  end
end

# ErrataParser
class DebianErrataParser
  attr_reader :info_state, :info_state_cmplt

  def initialize(verbose: false)
    @info_state = :init
    @info_state_cmplt = 1

    # Erratum might apply to packages of more than one release (e.g. stretch and jessie)
    # This option keeps source-package version for release that has not been processed by
    # add_binary_packages(), which makes it easier to make another run of
    # add_binary_packages() with another release's packages.
    # Setting this to false makes it easier to remove Errata not applicable for the
    # release, packages were added for, by removing all Errata with packages == []
    @option_keep_unsupported_source_packages = false

    @verbose = verbose
  end

  # find additional information for DSA's CVEs in cve_list
  # Adds to erratum:
  #   description: concatenation of all CVE-descriptions
  #   scope: the thread-scope ('local' of 'remote')
  #   severity: severity of the threat (e.g. 'medium')
  #   dbts_list: list of Debian Bug Tracking System IDs
  def add_cve_information(erratum, dsa, cve_list)
    description = []
    dsa.cve.each do |c|
      next unless cve_list.key?(dsa.package) &&
                  cve_list[dsa.package].key?(c)

      cve = cve_list[dsa.package][c]

      erratum.add_debian_bug cve['debianbug'] if cve.key? 'debianbug'
      erratum.scope = cve.fetch('scope', nil)
      description << cve['description']

      cve['releases'].each do |rel, data|
        next if !dsa.versions.key?(rel) || data['status'] != 'resolved'

        # WORKAROUND: currently DSA severities include '**' at the end
        erratum.severity = data['urgency'].delete('*')
      end
    end

    erratum.description = description.delete_if { |d| d.nil? || d.empty? }.join("\n\n")
  end

  def gen_debian_errata(dsa_list, cve_list)
    errata = []

    @info_state = :gen_errata
    info_step = 1.0 / dsa_list.length
    @info_state_cmplt = 0

    dsa_list.each do |dsa|
      @info_state_cmplt += info_step

      erratum = Erratum.new
      erratum.name = dsa.id
      erratum.title = "#{dsa.package} -- #{dsa.type}"
      # add time and timezone, otherwise conversion to UTC might change the date
      erratum.issued = "#{dsa.date} 00:00 UTC"
      dsa.cve&.each { |c| erratum.add_cve c }
      erratum.source_package = dsa.package

      dsa.versions.each do |rel, pkg_dat|
        pkg_dat.each do |pkg_name, pkg_version|
          erratum.add_package(pkg_name, pkg_version, release: rel)
        end
      end

      add_cve_information(erratum, dsa, cve_list) unless dsa.cve_empty?

      errata << erratum
    end
    errata
  end

  def metadata_add_entry(release, architecture, component)
    if @metadata[:releases].key? release
      @metadata[:releases][release][:architectures] << architecture
      @metadata[:releases][release][:components] << component
    else
      # init metadata
      @metadata[:releases][release] = {
        architectures: Set.new([architecture]),
        components: Set.new([component])
      }
    end
  end

  def metadata
    res = { releases: {} }
    @metadata[:releases].each do |rel, data|
      res[:releases][rel] = {
        architectures: data[:architectures].to_a,
        components: data[:components].to_a
      }
    end
    res
  end

  def get_versions(hsh)
    ret = {}
    hsh.each_value do |b|
      ret[b['version'].sub(/^\d+:/, '')] = b['version']
    end
    ret
  end

  def add_packages_ubuntu(erratum, release, data, architecture_whitelist, packages)
    versions = get_versions(data['sources'])
    versions.merge(get_versions(data['binaries']))
    data['archs'].each do |arch_name, arch|
      next if arch_name == 'source'
      next unless arch_name == 'all' || architecture_whitelist.nil? || architecture_whitelist.include?(arch_name)

      arch['urls'].each_key do |url|
        match = %r{/pool/(?<comp>[^/]+)/.*/(?<pkg_name>[^/_]*)_(?<version>[^_/]+)_(?<arch>[^_/]+)\.deb}.match(url)
        if match.nil?
          warn "#{erratum.name}: URL did not match: #{url}" if @verbose
        else
          found = false
          if packages.dig(match['arch'], release, match['pkg_name'])
            packages[match['arch']][release][match['pkg_name']].each do |v|
              if Debian::Dpkg.compare_versions v, 'ge', match['version']
                found = true
                break
              end
            end
          end

          if found
            erratum.add_package(
              match['pkg_name'],
              versions[match['version']] || match['version'],
              architecture: match['arch'],
              component: match['comp'],
              release: release
            )
            metadata_add_entry(release, match['arch'], match['comp'])
          elsif @verbose
            warn "#{erratum.name}: Package \"#{match['pkg_name']}_#{match['version']}\" for \"#{release} - #{match['arch']}\" doesn't exist in package list!"
          end
        end
      end
    end
  end

  def gen_ubuntu_errata(usn_db, packages, packages_by_name, release_whitelist=nil, architecture_whitelist=nil)
    @info_state = :gen_errata
    info_step = 1.0 / usn_db.length
    @info_state_cmplt = 0

    @metadata = { releases: {} }
    errata = []
    usn_db.each do |id, usn|
      @info_state_cmplt += info_step
      name = "USN-#{id}"
      begin
        erratum = Erratum.new
        erratum.name = name
        erratum.title = usn['title']
        erratum.description = usn['description']
        if usn.key? 'cves'
          usn['cves'].each do |cve|
            erratum.add_cve cve
          rescue RuntimeError => e
            raise unless e.message.start_with? 'Invalid CVE'
          end
        end
        erratum.issued = usn['timestamp']
        usn['releases'].each do |rel, dat|
          next if release_whitelist.is_a?(Array) && !release_whitelist.include?(rel)

          # ESM-Updates do not have 'archs' -> Fallback to alternative handling
          if dat.key?('archs') && !packages.empty?
            add_packages_ubuntu(erratum, rel, dat, architecture_whitelist, packages)
          elsif dat.key?('sources')
            # try to do it the debian-way: get_binary_packages_for_erratum_package()
            warn "#{name} has no architectures for release #{rel} -> using source-packages as fallback" if @verbose
            dat['sources'].each do |source_pkg, pkg|
              source_packages = [source_pkg]
              # make sure we use signed linux-images instead of unsigned ones!
              source_packages.unshift source_pkg.sub(/^linux/, 'linux-signed') if source_pkg =~ /^linux/

              package = {}
              pkg.each do |k, v|
                package[k.to_sym || key] = v
              end
              package[:release] = rel

              source_packages.each do |source|
                # skip if source not in packages_by_name
                unless packages_by_name.key? source
                  warn "#{source} not in package-list; for #{name} and release #{rel} -> skipping" if @verbose
                  next
                end

                # set source-package
                # if multiple sources are specified by USN, we currently only take the last one!
                # which should not be the case :fingerscrossed:
                erratum.source_package = source

                pkgs = get_binary_packages_for_erratum_package(
                  source,
                  package,
                  packages_by_name[source],
                  architecture_whitelist
                )
                pkgs.each do |binpkg|
                  erratum.add_package(
                    binpkg[:name],
                    binpkg[:version],
                    architecture: binpkg[:architecture],
                    release: binpkg[:release],
                    component: binpkg[:component]
                  )
                  metadata_add_entry(binpkg[:release], binpkg[:architecture], binpkg[:component])
                end
              end
            end
          elsif @verbose
            warn "#{name} has no architectures for release #{rel} -> skipping"
          end
        end
        # ignore errata without package-information
        next if erratum.packages.empty?

        errata << erratum
      rescue StandardError
        warn "At #{name}:"
        raise
      end
    end
    errata
  end

  def add_binary_packages_from_file(errata, package_json_path, releases=nil, architecture_whitelist=nil, special_kernel_pkg_collection=nil)
    add_binary_packages(
      errata,
      JSON.parse(File.read(package_json_path)),
      releases: releases,
      architecture_whitelist: architecture_whitelist,
      special_kernel_pkg_collection: special_kernel_pkg_collection
    )
  end

  def add_binary_packages(errata, packages, releases: ['stretch'], architecture_whitelist: nil, special_kernel_pkg_collection: nil)
    @info_state = :add_binaries
    @info_state_cmplt = 0
    info_step = 1.0 / errata.length

    errata.each do |erratum|
      @info_state_cmplt += info_step

      next if erratum.packages.empty?

      erratum.replace_packages do |p|
        new = []
        if releases.nil? || releases.include?(p[:release])
          if packages.key? p[:name]
            new = get_binary_packages_for_erratum_package(
              erratum.source_package,
              p,
              packages[p[:name]],
              architecture_whitelist
            )
            #  On Debian, there are differnet source packages which are used to build the linux kernel packages
            #    linux -> is used to create the unsigned linux images
            #    linux-signed-XX (e.g. linux-signed-amd64) is used to build signed linux image which runs on secureboot enabled systems
            if erratum.source_package == 'linux' && special_kernel_pkg_collection&.include?(p[:release])
              architecture_whitelist.each do |arch|
                source_pkg = "linux-signed-#{arch}"
                packages.keys.select { |package_name| package_name.start_with? source_pkg }.each do |package_name|
                  new += get_binary_packages_for_erratum_package(
                    source_pkg,
                    p,
                    packages[package_name],
                    architecture_whitelist
                  )
                end
              end
            end
          end
          # return new value to append to package list in erratum
          new
        elsif @option_keep_unsupported_source_packages
          # wrong release-name, keep old value?
          p
        else
          new
        end
      end
    end
  end

  def get_binary_packages_for_erratum_package(source_pkg, pkg, packages, architecture_whitelist)
    res = []
    packages.each do |arch_name, arch|
      next unless architecture_whitelist.nil? || arch_name == 'all' || architecture_whitelist.include?(arch_name)

      arch.each do |deb|
        next if pkg[:release] != deb['release']

        # Unfortunately, a special handling for packages created from the linux source need to be done.
        # - In one debian release, multiple linux versions (= stream) can be shipped.
        # - Therefore, the linux kernel package NAMES are like linux-image-4.19.0-14.
        # - A full package including version would therefore look like linux-image-4.19.0-14_4.19.171-2_amd64.deb.
        # - A Debian DSA is released based on a specific version like 4.19.171-2 which should fix the issue.
        # - The erratum should only contain packages of this linux kernel stream '4.19.171' and not e.g. for '4.19.194'
        # - The Debian DSA can be fixed with versions greater or equal '4.19.171-2' (4.19.171-3 or 4.19.171-4)
        if source_pkg == 'linux' || source_pkg.start_with?('linux-signed')
          deb_main_version = deb['version'].rpartition('-')[0]
          deb_main_version = deb['version'] if deb_main_version.empty?
          pkg_main_version = pkg[:version].rpartition('-')[0]
          pkg_main_version = pkg[:version] if pkg_main_version.empty?
          next if deb_main_version != pkg_main_version
        end

        # version from packages must be 'greater or equal' to the version requested by DSA
        if Debian::Dpkg.compare_versions deb['version'], 'ge', pkg[:version]
          res << {
            name: deb['name'],
            version: deb['version'],
            architecture: deb['arch'],
            release: deb['release'],
            component: deb['comp']
          }
        elsif @verbose
          warn "Skipping #{deb['name']} because available version is smaller than fixed version: #{deb['version']} < #{pkg[:version]}"
        end
      end
    end
    res
  end
end

if $PROGRAM_NAME == __FILE__
  # always interpret files as UTF-8 instead of US-ASCII
  Encoding.default_external = 'UTF-8'

  TEMPDIR = '/tmp/errata_parser_cache'
  extend Downloader

  type = ARGV[0]
  parser = DebianErrataParser.new
  Thread.new do
    $stderr.puts
    line = ''
    loop do
      # clean line
      $stderr.print "#{' ' * line.length}\r"

      line = "#{(parser.info_state_cmplt * 100).round}% #{parser.info_state}"
      $stderr.print "#{line}\r"
      sleep 0.1
    end
  end

  case type
  when 'debian'
    ## Debian
    tempdir = Pathname.new(File.join(TEMPDIR, 'debian'))
    tempdir.mkpath
    dsa_list = download_file_cached('https://salsa.debian.org/security-tracker-team/security-tracker/raw/master/data/DSA/list', File.join(tempdir, 'dsa.list'))
    dla_list = download_file_cached('https://salsa.debian.org/security-tracker-team/security-tracker/raw/master/data/DLA/list', File.join(tempdir, 'dla.list'))
    cve_file = download_file_cached('https://security-tracker.debian.org/tracker/data/json', File.join(tempdir, 'cve.json'))
    errata = parser.gen_debian_errata(DSA.parse_dsa_list_str(dsa_list), JSON.parse(cve_file))
    errata += parser.gen_debian_errata(DSA.parse_dsa_list_str(dla_list), JSON.parse(cve_file))
    # parser.add_binary_packages_from_file(errata, 'packages_everything.json')
    parser.add_binary_packages_from_file(errata, 'packages_everything.json', ['bullseye'], ['amd64'], ['bullseye'])

    # filter empty package-lists
    # errata.delete_if { |x| x['packages'].nil? || x['packages'].empty? }

  when 'debian_test_record'
    dsa_list = File.read('test/data/dsa.list')
    cve_file = File.read('test/data/cve.json')
    errata = parser.gen_debian_errata(DSA.parse_dsa_list_str(dsa_list), JSON.parse(cve_file))
    parser.add_binary_packages_from_file(errata, 'test/data/packages_everything_debian.json', ['buster', 'bullseye'], ['amd64'], ['bullseye'])

  when 'ubuntu'
    ## Ubuntu
    require 'bzip2/ffi'
    require 'stringio'

    tempdir = Pathname.new(File.join(TEMPDIR, 'ubuntu'))
    tempdir.mkpath

    HTTPDEBUG = true
    usn_db = download_file_cached('https://usn.ubuntu.com/usn-db/database.json.bz2', File.join(tempdir, 'database.json.bz2'))
    # usn_db = download_file_cached('https://usn.ubuntu.com/usn-db/database-all.json.bz2', File.join(tempdir, 'database-all.json.bz2'))

    # TODO: verify checksum
    # verify_checksum(usn_db, 'https://usn.ubuntu.com/usn-db/database.json.sha256', Digest::SHA256)

    packages = JSON.parse(File.read('packages_everything.json'))
    packages_by_name = JSON.parse(File.read('test/data/packages_everything_ubuntu_debstyle.json'))
    errata = parser.gen_ubuntu_errata(JSON.parse(Bzip2::FFI::Reader.read(StringIO.new(usn_db))), packages, packages_by_name, ['bionic'], ['amd64'])

  when 'ubuntu_test_record'
    require 'bzip2/ffi'
    require 'stringio'

    usn_db_f = File.open('test/data/database.json.bz2', 'rb')

    packages = JSON.parse(File.read('test/data/packages_everything_ubuntu.json'))
    errata = parser.gen_ubuntu_errata(JSON.parse(Bzip2::FFI::Reader.read(usn_db_f)), packages, {}, ['bionic'], ['amd64'])
    usn_db_f.close

  when 'ubuntu-esm_test_record'
    require 'bzip2/ffi'
    require 'stringio'

    usn_db_f = File.open('test/data/database.json.bz2', 'rb')

    packages_by_name = JSON.parse(File.read('test/data/packages_everything_ubuntu_debstyle.json'))
    errata = parser.gen_ubuntu_errata(JSON.parse(Bzip2::FFI::Reader.read(usn_db_f)), {}, packages_by_name, ['xenial'], ['amd64'])
    usn_db_f.close

  else
    warn "Unsupported option #{type}"
    exit 1
  end

  arr = []
  errata.sort { |x, y| y.name <=> x.name }.each do |e|
    # remove Errata without packages
    next if e.packages.empty?

    erratum_hash = e.to_h
    # sort packages roughly to make comparing changes of test-data easier.
    erratum_hash['packages'].sort_by! { |pkg| [pkg['name'], pkg['version'], pkg['release']] }
    arr << erratum_hash
  end
  puts arr.to_yaml
  # puts errata.to_json
end
