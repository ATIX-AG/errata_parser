# frozen_string_literal: true

require 'bzip2/ffi'
require 'byebug'

require_relative '../parse_dsalist'
require_relative '../errata_parser'
require_relative '../downloader'
require_relative '../debRelease'

releases = ['stretch', 'bullseye']
test_path = File.dirname __FILE__
data_path = File.join test_path, 'data'

config = load_config(File.join(test_path, '..', 'default_config.json'))
config_debian = config['debian']
config_ubuntu = config['ubuntu']

# gen DSA-List
config['debian']['dsa_list_url']

lists = [
  {
    file: File.join(data_path, 'dsa.list'),
    url: config_debian['dsa_list_url']
  },
  {
    file: File.join(data_path, 'dla.list'),
    url: config_debian['dla_list_url']
  }
]

warn 'receive DSA/DLA lists (Debian)...'
class Download
  include Downloader
end
cve_ids = []
lists.each do |list|
  dsa_list = DSA.parse_dsa_list_str(Download.new.download_file_cached(list[:url]))

  File.open(list[:file], 'w') do |f|
    dsa_list.each do |dsa|
      cve_ids |= dsa.cve
      f << dsa.to_orig(releases)
    end
  end
end

# gen CVE-List
warn 'receive CVE list (Debian)...'
cve_list = JSON.parse(Download.new.download_file_cached(config_debian['cve_list_url']))
cve_list_filtered = {}
cve_list.each do |package, cves|
  cves_filtered = {}
  cves.each do |cve_id, cve|
    releases = cve['releases'].select { |release, _pkgs| releases.include? release }
    if cve_ids.include?(cve_id) || !releases.empty?
      cves_filtered[cve_id] = cve.clone
      cves_filtered[cve_id]['releases'] = releases
    end
  end
  cve_list_filtered[package] = cves_filtered unless cves_filtered.empty?
end

File.open(File.join(data_path, 'cve.json'), 'w') do |f|
  f.write JSON.dump cve_list_filtered
end

# gen USN-database
warn 'receive USN list (Ubuntu)...'

rel_whitelist = ['bionic', 'xenial']
usn_db = Download.new.download_file_cached(config_ubuntu['usn_list_url'])
usn_db_filtered = {}
JSON.parse(Bzip2::FFI::Reader.read(StringIO.new(usn_db))).each do |usn_id, usn_data|
  releases_data = usn_data['releases'].select { |r, _dat| rel_whitelist.include? r }
  next if releases_data.empty?

  usn_db_filtered[usn_id] = usn_data.clone.merge('releases' => releases_data)
end
Bzip2::FFI::Writer.write(
  File.join(data_path, 'database.json.bz2'),
  JSON.dump(usn_db_filtered)
)

## Generate package-files

# always interpret files as UTF-8 instead of US-ASCII
Encoding.default_external = 'UTF-8'

HTTPDEBUG = true

['debian', 'ubuntu', 'ubuntu_debstyle'].each do |type|
  case type
  when 'debian'
    suites = [
      'stretch/updates',
      'bullseye-security'
    ]
    repository_url = config_debian['repository']['repo_url']
  when 'ubuntu'
    suites = [
      'bionic-security'
    ]
    repository_url = config_ubuntu['repository']['repo_url']
  when 'ubuntu_debstyle'
    suites = [
      'xenial-infra-security'
    ]
    url = URI.parse(config['ubuntu-esm']['repository']['repo_url'])
    # ask for credentials!
    puts 'Ubuntu-ESM repository requires credentials!'
    printf 'user: '
    url.user = gets.strip
    printf 'pass: '
    url.password = gets.strip
    next if url.user.empty?

    repository_url = url.to_s
  else
    warn "Unsupported option #{type}"
    exit 1
  end

  threads = []
  pckgs = []
  suites.each do |s|
    threads << Thread.new do
      warn "Loading Release for #{s.inspect}"
      debrel = DebRelease.new(repository_url, s)

      debrel.whitelist_arch = ['amd64', 'all']
      debrel.whitelist_comp = ['main']
      debrel.release_name = 'bullseye' if s == 'bullseye-security'

      warn "From #{s.inspect} get archs:#{debrel.architectures.inspect} and comps: #{debrel.components.inspect}"

      pckgs << debrel.all_packages
    end
  end

  threads.each(&:join)

  packages = {}

  case type
  when 'debian', 'ubuntu_debstyle'
    pckgs.each do |p|
      DebRelease.assemble_debian_packages(packages, p)
    end
  when 'ubuntu'
    pckgs.each do |p|
      DebRelease.assemble_ubuntu_packages(packages, p)
    end
  else
    warn "Unsupported option #{type}"
    exit 1
  end

  output_filename = "packages_everything_#{type}.json"
  File.write(
    File.join(data_path, output_filename),
    JSON.dump(packages)
  )
end
