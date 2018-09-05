require 'debian'
require 'time'

require_relative 'downloader'

TEMPDIR = '/tmp/errataparser_cache'.freeze

class DebRelease
  include Downloader

  attr_reader :data, :files
  attr_accessor :suite, :base_url
  RE_FILES = /^\s*(?<digest>[0-9a-f]+)\s+(?<size>\d+)\s*(?<path>\S.*)$/

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
    dir = "#{TEMPDIR}/#{URI(@base_url).hostname}/#{subdir}"
    created = ''
    dir.split('/').each do |d|
      next if d.empty?
      created += "/#{d}"
      Dir.mkdir created unless Dir.exist? created
    end
    created
  end

  def release_name
    @data['codename'] || @data['suite']
  end

  def parse(release_text)
    state = nil
    release_text.each_line do |line|
      if line[0] !~ /\s/
        state = nil
        key,value = line.split ':'
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
      else
        fileinfo = RE_FILES.match(line)
        if fileinfo
          @files[fileinfo['path']] = {} unless @files.key? fileinfo['path']
          @files[fileinfo['path']]['size'] = fileinfo['size']
          @files[fileinfo['path']][state] = fileinfo['digest']
        else
          warn "line could not be matched: #{line.inspect}"
        end
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

  def self.get_all_packages(uri, suite, components=nil, architectures=nil)
    rel = new uri, suite

    packages = {}
    architectures = rel.data['architectures'] + ['all'] if architectures.nil?
    components = Debian::COMPONENT if components.nil?
    architectures.each do |arch|
      components.each do |comp|
        rel.get_package(comp, arch).each do |p,d|
          packages[d.source] = {} unless packages.key? d.source
          packages[d.source][arch] = [] unless packages[d.source].key? arch
          packages[d.source][arch] << {
            'name' => p,
            'version' => d.version,
            'arch' => arch,
            'comp' => comp,
            'release' => rel.release_name
          }
        end
      end
    end
    packages
  end
end

if $PROGRAM_NAME == __FILE__
  require 'json'

  HTTPDEBUG = true
  packages = DebRelease.get_all_packages 'http://security.debian.org/debian-security', 'stretch/updates'

  puts JSON.dump packages

  #rel.get_package('main', 'amd64').each do |p,d|
  #  puts p.inspect
  #  puts "#{d.source} @ #{d.version}"
  #end
end
