#!/usr/bin/env ruby

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

class Erratum
  attr_accessor :title, :name, :cves, :package, :fixed_version
  attr_accessor :dbts_bugs
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
      'affected_source_package' => package,
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
  #TODO too static, what if a new value is introduced?
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

  def initialize(verbose=false)
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
      dsa.cve.each { |c| erratum.add_cve c } if dsa.cve
      erratum.package = dsa.package

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
        components: Set.new([component]),
      }
    end
  end

  def metadata
    res = { releases: {} }
    @metadata[:releases].each do |rel, data|
      res[:releases][rel] = {
        architectures: data[:architectures].to_a,
        components: data[:components].to_a,
      }
    end
    res
  end

  def get_versions(hsh)
    ret = {}
    hsh.values.each do |b|
      ret[b['version'].sub(/^\d+:/, '')] = b['version']
    end
    ret
  end

  def add_packages_ubuntu(erratum, release, data, architecture_whitelist)
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
          erratum.add_package(
            match['pkg_name'],
            versions[match['version']] || match['version'],
            architecture: match['arch'],
            component: match['comp'],
            release: release
          )
          metadata_add_entry(release, match['arch'], match['comp'])
        end
      end
    end
  end

  def gen_ubuntu_errata(usn_db, release_whitelist=nil, architecture_whitelist=nil)
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
            begin
              erratum.add_cve cve
            rescue RuntimeError => e
              raise unless e.message.start_with? 'Invalid CVE'
            end
          end
        end
        erratum.issued = usn['timestamp']
        usn['releases'].each do |rel, dat|
          next if release_whitelist.is_a?(Array) && !release_whitelist.include?(rel)

          unless dat.key?('archs')
            warn "#{name} has no architectures for release #{rel}" if @verbose
            next
          end
          add_packages_ubuntu(erratum, rel, dat, architecture_whitelist)
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

  def add_binary_packages_from_file(errata, package_json_path, releases=nil, architecture_whitelist=nil)
    add_binary_packages(
      errata,
      JSON.parse(File.read(package_json_path)),
      releases: releases,
      architecture_whitelist: architecture_whitelist
    )
  end

  def add_binary_packages(errata, packages, releases: ['stretch'], architecture_whitelist: nil)
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
              p,
              packages[p[:name]],
              architecture_whitelist
            )
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

  def get_binary_packages_for_erratum_package(pkg, packages, architecture_whitelist)
    res = []
    packages.each do |arch_name, arch|
      next unless architecture_whitelist.nil? || arch_name == 'all' || architecture_whitelist.include?(arch_name)

      arch.each do |deb|
        next if pkg[:release] != deb['release']

        # version from packages must be 'greater or equal' to the version requested by DSA
        if Debian::Dpkg.compare_versions deb['version'], 'ge', pkg[:version]
          res << {
            name: deb['name'],
            version: pkg[:version],
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

  TEMPDIR = '/tmp/errata_parser_cache'.freeze
  extend Downloader

  type = ARGV[0]
  parser = DebianErrataParser.new
  Thread.new do
    STDERR.puts
    line = ''
    loop do
      # clean line
      STDERR.print "#{' ' * line.length}\r"

      line = "#{(parser.info_state_cmplt * 100).round}% #{parser.info_state}"
      STDERR.print "#{line}\r"
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
    #parser.add_binary_packages_from_file(errata, 'packages_everything.json')
    parser.add_binary_packages_from_file(errata, 'packages_everything.json', ['buster', 'stretch'], ['amd64'])

    # filter empty package-lists
    #errata.delete_if { |x| x['packages'].nil? || x['packages'].empty? }

  when 'debian_test_record'
    dsa_list = File.read('test/data/dsa.list')
    cve_file = File.read('test/data/cve.json')
    errata = parser.gen_debian_errata(DSA.parse_dsa_list_str(dsa_list), JSON.parse(cve_file))
    parser.add_binary_packages_from_file(errata, 'test/data/packages_everything.json', ['stretch'], ['amd64'])

  when 'ubuntu'
    ## Ubuntu
    require 'bzip2/ffi'
    require 'stringio'

    tempdir = Pathname.new(File.join(TEMPDIR, 'ubuntu'))
    tempdir.mkpath

    HTTPDEBUG = true
    usn_db = download_file_cached('https://usn.ubuntu.com/usn-db/database.json.bz2', File.join(tempdir, 'database.json.bz2'))
    #usn_db = download_file_cached('https://usn.ubuntu.com/usn-db/database-all.json.bz2', File.join(tempdir, 'database-all.json.bz2'))

    # TODO verify checksum
    #verify_checksum(usn_db, 'https://usn.ubuntu.com/usn-db/database.json.sha256', Digest::SHA256)

    errata = parser.gen_ubuntu_errata JSON.parse(Bzip2::FFI::Reader.read(StringIO.new(usn_db))), ['bionic'], ['amd64']

  when 'ubuntu_test_record'
    require 'bzip2/ffi'
    require 'stringio'

    usn_db_f = File.open('test/data/database.json.bz2', 'rb')
    errata = parser.gen_ubuntu_errata JSON.parse(Bzip2::FFI::Reader.read(usn_db_f)), ['bionic'], ['amd64']
    usn_db_f.close

  else
    warn "Unsupported option #{type}"
    exit 1
  end

  arr = []
  #errata.sort{ |x, y| y.name <=> x.name }.each do |e|
  errata.each do |e|
    # remove Errata without packages
    arr << e.to_h unless e.packages.empty?
  end
  puts arr.to_yaml
  #puts errata.to_json
end
