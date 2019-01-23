#!/usr/bin/env ruby

require 'debian'
require 'time'
require 'pathname'

require_relative 'downloader'

class DebRelease
  include Downloader

  # rubocop:disable Style/ClassVars
  @@tempdir = '/tmp/errata_parser_cache/debian'
  # rubocop:enable Style/ClassVars

  attr_reader :data, :files
  attr_accessor :suite, :base_url
  attr_accessor :whitelist_arch, :whitelist_comp
  RE_FILES = /^\s*(?<digest>[0-9a-f]+)\s+(?<size>\d+)\s*(?<path>\S.*)$/.freeze

  def initialize(uri=nil, suite='stable')
    init
    url = URI(uri)
    return unless url.scheme =~ /^http(s)?$/

    @base_url = uri
    @suite = suite
    cachedir = create_cache
    parse download_file_cached "#{release_base_url}/Release", "#{cachedir}/Release"
  end

  def init
    @data = {}
    @files = {}
    @base_url = nil
  end

  def create_cache(subdir='')
    dir = Pathname.new(File.join(@@tempdir, @suite, URI(@base_url).hostname, subdir))
    dir.mkpath

    dir
  end

  def release_name
    @data['codename'] || @data['suite']
  end

  def parse(release_text)
    state = nil
    release_text.each_line do |line|
      if line[0] !~ /\s/
        state = nil
        key, value = line.split ':'
        key = key.strip.downcase

        store = case key
                when 'date', 'valid-until'
                  Time.parse value
                when 'architectures', 'components'
                  value.split ' '
                when 'md5sum', 'sha1', 'sha256'
                  state = key
                  next
                else
                  value.strip
                end
        @data[key] = store
      elsif (fileinfo = RE_FILES.match(line))
        @files[fileinfo['path']] = {} unless @files.key? fileinfo['path']
        @files[fileinfo['path']]['size'] = fileinfo['size']
        @files[fileinfo['path']][state] = fileinfo['digest']
      else
        warn "line could not be matched: #{line.inspect}"
      end
    end
  end

  def release_base_url
    "#{@base_url}/dists/#{@suite}"
  end

  def get_package(component, architecture)
    rel_path = "#{component}/binary-#{architecture}"
    paths = @files.keys.select { |path| path.start_with? "#{rel_path}/Packages" }
    # sort-reverse to prefer Packages.xz files before .gz and plain-files
    paths = paths.sort.reverse
    raise 'base_url not set' if @base_url.nil?

    cache_dir = create_cache rel_path
    # check cached-files first!
    paths_exist = paths.select { |p| File.exist? "#{cache_dir}/#{p.split('/').last}" }
    paths = paths_exist + (paths - paths_exist)

    paths.each do |p|
      begin
        basefilename = p.split('/').last
        path = "#{cache_dir}/#{basefilename}"
        data = download_file_cached "#{release_base_url}/#{p}", path
        plainfile = "#{cache_dir}/Packages.plain"
        File.open(plainfile, 'w') do |f|
          case basefilename.downcase
          when 'packages.xz'
            require 'xz'
            f << XZ.decompress(data)
          when 'packages.gz'
            require 'zlib'
            f << Zlib.gunzip(data)
          else
            f << data
          end
        end
        return Debian::Packages.new(plainfile)
      rescue StandardError => e
        warn "#{e} for #{p.inspect}"
        File.unlink path if File.exist? path
      ensure
        File.unlink plainfile if plainfile && File.exist?(plainfile)
      end
    end
  end

  def architectures
    arch = Set.new(data['architectures'])
    arch &= Set.new(whitelist_arch) if whitelist_arch
    # make sure architecture 'all' is always present
    arch += Set.new(['all'])
    arch.to_a
  end

  def components
    # must work around debian-security having components like 'updates/main'
    # but paths use 'main'
    comp = Set.new(data['components'].map { |c| c.split('/').last })
    comp &= Set.new(whitelist_comp) if whitelist_comp
    comp.to_a
  end

  def all_packages
    packages = {}
    architectures.each do |arch|
      components.each do |comp|
        get_package(comp, arch).each do |p, d|
          # necessary because sometimes 'all'-packages are also in the binary Package-files
          architecture = d.info['Architecture'] if d.fields.include? 'Architecture'
          architecture = arch if architecture.nil?

          packages[d.source] = {} unless packages.key? d.source
          packages[d.source][architecture] = [] unless packages[d.source].key? architecture
          packages[d.source][architecture] << {
            'name' => p,
            'version' => d.version,
            'arch' => architecture,
            'comp' => comp,
            'release' => release_name
          }
          # make sure we do not have duplicates
          packages[d.source][architecture].uniq!
        end
      end
    end
    packages
  end

  def self.tempdir=(dirname)
    @@tempdir = dirname
  end

  def self.get_all_packages(uri, suite, components=nil, architectures=nil)
    rel = new(uri, suite)
    rel.whitelist_arch = architectures unless architectures.nil?
    rel.whitelist_comp = components unless components.nil?
    rel.all_packages
  end
end

if $PROGRAM_NAME == __FILE__
  require 'json'

  # always interpret files as UTF-8 instead of US-ASCII
  Encoding.default_external = 'UTF-8'

  HTTPDEBUG = true
  suites = [
    'jessie/updates',
    'stretch/updates',
    'buster/updates'
  ]
  threads = []
  pckgs = []
  suites.each do |s|
    threads << Thread.new do
      warn "Loading Release for #{s.inspect}"
      debrel = DebRelease.new('http://security.debian.org/debian-security', s)

      debrel.whitelist_arch = ['amd64', 'all']
      debrel.whitelist_comp = ['main']

      warn "From #{s.inspect} get archs:#{debrel.architectures.inspect} and comps: #{debrel.components.inspect}"

      pckgs << debrel.all_packages
    end
  end

  threads.each(&:join)

  packages = {}
  pckgs.each do |p|
    p.each do |pkg_name, pkg|
      packages[pkg_name] = {} unless packages.key? pkg_name
      pkg.each do |arch_name, arch|
        packages[pkg_name][arch_name] = [] unless packages[pkg_name].key? arch_name
        packages[pkg_name][arch_name].concat arch
      end
    end
  end

  puts JSON.dump packages

  #rel.get_package('main', 'amd64').each do |p, d|
  #  puts p.inspect
  #  puts "#{d.source} @ #{d.version}"
  #end
end
