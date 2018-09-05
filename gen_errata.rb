#!/usr/bin/env ruby

require 'json'
require 'yaml'
require 'date'
require 'debian'

require_relative 'parse_dsalist'
require_relative 'downloader'

URGENCY_PRIO = [
  'not yet assigned',
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

class DebianErrataParser
  attr_reader :info_state, :info_state_cmplt

  def initialize
    @info_state = :init
    @info_state_cmplt = 1
  end

  def get_max_prio_idx(map, old, new)
    old ||= -1
    idx = map.index { |x| new =~ /#{x}/ }
    if idx.nil?
      old
    else
      [old, idx].max
    end
  end

  def gen_debian_errata(dsa_list, cve_list)
    errata = {}

    @info_state = :gen_errata
    info_step = 1.0 / dsa_list.length
    @info_state_cmplt = 0

    dsa_list.each do |dsa|
      @info_state_cmplt += info_step

      dsa = dsa.to_h if dsa.is_a? DSA
      erratum = {}
      erratum['title'] = "#{dsa['package']} -- #{dsa['type']}"
      #erratum['issued'] = Date.strptime(dsa['date'], '%d %b %Y')
      erratum['issued'] = dsa['date']
      erratum['cves'] = dsa['cve'] if dsa.key? 'cve'
      erratum['affected_source_package'] = dsa['package']

      description = []
      packages = {}

      if dsa.key?('cve') && !dsa['cve'].empty?
        #cves = dsa['cve'].map{ |c| cve_list[dsa['package']]&.fetch(c, nil)&.merge('name' => c) }
        cves = dsa['cve'].map do |c|
          if cve_list.key?(dsa['package']) && cve_list[dsa['package']].key?(c) && cve_list[dsa['package']][c].is_a?(Hash)
            cve_list[dsa['package']][c].merge('name' => c)
          end
        end
        cves.delete_if(&:nil?)

        debianbugs = []
        scope_idx = -1
        severity_idx = -1
        cves.each do |cve|
          debianbugs << cve['debianbug'] if cve.key? 'debianbug'
          scope_idx = get_max_prio_idx(SCOPE_PRIO, scope_idx, cve.fetch('scope', nil))
          description << cve['description']

          cve['releases'].each do |rel,data|
            next if data['status'] != 'resolved'
            packages[rel] = { version: nil } unless packages.key? rel

            packages[rel] = {
              version: data['fixed_version']
            }

            severity_idx = get_max_prio_idx(URGENCY_PRIO, severity_idx, data['urgency'])
          end

          erratum['scope'] = SCOPE_PRIO[scope_idx]
          erratum['severity'] = URGENCY_PRIO[severity_idx]
        end

        erratum['packages'] = []
        packages.each do |rel,data|
          erratum['packages'].append(
            'name' => dsa['package'],
            'version' => data[:version],
            'release' => rel
          )
        end
        erratum['dbts_bugs'] = debianbugs unless debianbugs.empty?
        erratum['description'] = description.delete_if { |d| d.nil? || d.empty? }.join("\n\n")

      end

      errata[dsa['name']] = erratum
      #warn erratum.inspect
      #break
    end
    errata
  end

  def gen_ubuntu_errata(usn_db, release_whitelist=nil, architecture_whitelist=nil)
    dict = [
      'title',
      'description',
      'cves'
    ]
    errata = {}
    usn_db.each do |id,usn|
      erratum = usn.select { |dat| dict.include? dat }
      erratum['issued'] = Time.at(usn['timestamp']).strftime('%d %b %Y')
      packages = []
      #packages_arch = {}
      packages_arch = []
      usn['releases'].each do |rel,dat|
        next if release_whitelist.is_a?(Array) && !release_whitelist.include?(rel)
        #packages_arch[rel] = {}
        dat['binaries'].each do |pkg,info|
          begin
            raise ParserException.new('Package without version information', id, rel, pkg) unless info.key? 'version'
            packages << {
              'name' => pkg,
              'version' => info['version'],
              'release' => rel
            }
          rescue RuntimeError => e
            warn e
          end
        end

        unless dat.key?('archs')
          warn "USN-#{id} has no architectures for release #{rel}"
          next
        end
        arch_bins = {}
        archs = []
        dat['archs'].each do |arch_name,arch|
          next if arch_name == 'source'
          next unless arch_name == 'all' || architecture_whitelist.nil? || architecture_whitelist.include?(arch_name)
          #packages_arch[rel][arch_name] = []

          archs << arch_name
          arch['urls'].each_key do |url|
            match = %r{/(?<pkg_name>[^/_]*)_(?<version>[^_/]+)_(?<arch>[^_/]+)\.[ud]?deb}.match(url)
            if match.nil?
              warn "URL did not match: #{url}"
            else
              arch_bins[match['pkg_name']] = [] unless arch_bins.key? match['pkg_name']
              arch_bins[match['pkg_name']] << match.named_captures
              packages_arch << {
              #packages_arch[rel][arch_name] << {
                'name' => match['pkg_name'],
                'version' => match['version'],
                'arch' => match['arch'],
                'release' => rel
              }
            end
          end
        end
        ###TEST START
        #arch_bins.each do |k,v|
        #  archs_local = v.map { |x| x['arch'] }
        #  warn "USN-#{id}: Too few versions of '#{k}' (missing: #{archs_local & archs})" if v.length != archs.length
        #end
        ###TEST END
      end
      next if packages.empty?
      #erratum['packages'] = packages
      erratum['packages'] = packages_arch
      errata["USN-#{id}"] = erratum
    end
    errata
  end

  def add_binary_packages_from_file(errata, package_json_path)
    add_binary_packages(errata, JSON.parse(File.read(package_json_path)))
  end

  def add_binary_packages(errata, packages)
    @info_state = :add_binaries
    @info_state_cmplt = 0
    info_step = 1.0 / errata.length
    errata.each do |_name,erratum|
      @info_state_cmplt += info_step
      next if erratum['packages'].nil?
      new = {}
      erratum['packages'].each do |p|
        # FIXME hardcoded release
        release = 'stretch'
        if p['release'] == release
          new[p['release']] = {} unless new.key? p['release']
          if packages.key? p['name']
            packages[p['name']].each do |arch_name,arch|
              new[p['release']][arch_name] = [] unless new[p['release']].key? arch_name

              arch.each do |deb|
                # version from packages must be 'greater or equal' to the version requested by DSA
                if Debian::Dpkg.compare_versions deb['version'], 'ge', p['version']
                  new[p['release']][arch_name].append(deb.clone)
                else
                  warn "Skipping #{deb['name']} because available version is smaller than fixed version: #{deb['version']} < #{p['version']}"
                end
              end
            end
          end
        end
        erratum['packages'] = new
      end
    end
  end
end

if $PROGRAM_NAME == __FILE__
  extend Downloader

  type = ARGV[0]
  parser = DebianErrataParser.new
  thr = Thread.new do
    STDERR.puts
    line = ''
    loop do
      # clean line
      STDERR.print "#{' '*line.length}\r"

      line = "#{(parser.info_state_cmplt * 100).round}% #{parser.info_state}"
      STDERR.print "#{line}\r"
      sleep 0.1
    end
  end

  if type == 'debian'
    ## Debian
    dsa_list = download_file_cached('https://salsa.debian.org/security-tracker-team/security-tracker/raw/master/data/DSA/list', 'test_data/dsa.list')
    cve_file = download_file_cached('https://security-tracker.debian.org/tracker/data/json', 'test_data/cve.json')
    #warn File.read("test_data/cve.json")[0,255]
    errata = parser.gen_debian_errata(DSA.parse_dsa_list_str(dsa_list), JSON.parse(cve_file))
    parser.add_binary_packages_from_file(errata, 'packages_everything.json')

    # filter empty package-lists
    errata.delete_if { |_k, x| x['packages'].nil? || x['packages'].empty? }

  elsif type == 'ubuntu'
    ## Ubuntu
    #usn_db = download_file_cached('https://usn.ubuntu.com/usn-db/database.json', 'test_data/database.json')
    usn_db = File.read('test_data/database.json')
    # TODO verify checksum
    #verify_checksum(usn_db, 'https://usn.ubuntu.com/usn-db/database.json.sha256', Digest::SHA256)

    errata = parser.gen_ubuntu_errata(JSON.parse(usn_db), ['bionic'], ['amd64'])

  else
    errata = download_file_cached('http://localhost/', '/tmp/test')
  end


  puts errata.to_yaml
  #puts errata.to_json
end
