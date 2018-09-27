#!/usr/bin/env ruby

require 'optparse'
require_relative 'gen_errata'
require_relative 'debRelease'
require_relative 'check_config'

# always interpret files as UTF-8 instead of US-ASCII
Encoding.default_external = 'UTF-8'

DEFAULT_CONF_FILE = 'config.json'.freeze
DEFAULT_CONF = {
  'tempdir' => '/tmp/errataparser_cache',
}.freeze

def fatal(message, code=42, show_help=false)
  warn message
  warn @opts if show_help
  exit code
end

def get_filename(os_name, type=:errata)
  "#{os_name}_#{type}.json"
end

def parse_commandline
  options = {
    config: DEFAULT_CONF_FILE,
  }
  @opts = OptionParser.new
  @opts.banner = 'Usage: errata_parser.rb [options]'

  @opts.on('-c', '--config FILE', String, "Use JSON-config from FILE (default: #{DEFAULT_CONF_FILE.inspect})") do |c|
    options[:config] = c
  end

  @opts.on('-d', '--debian PATH', String,
           "Parse Debian DSAs as Errata to #{get_filename(:debian)} in PATH") do |d|
    options[:debian] = d
  end

  @opts.on('-u', '--ubuntu PATH', String,
           "Parse Ubuntu USNs as Errata to #{get_filename(:ubuntu)} in PATH") do |u|
    options[:ubuntu] = u
  end

  @opts.on('-v', '--[no-]verbose', 'Run verbosely') do |v|
    options[:verbose] = v
    #HTTPDEBUG = v
  end

  @opts.on('-m', '--[no-]metadata', 'Create metadata files per Errata-file') do |m|
    options[:metadata] = m
  end

  @opts.on('-h', '--help', 'Prints this help') do
    puts @opts
    exit 1
  end
  @opts.parse!
  options
end

def write_json_file(filename, json_data, name: '', verbose: false)
  File.open(filename, 'w') do |f|
    warn "Writing #{name} to #{filename.inspect}" if verbose
    f << json_data.to_json
    #f << json_data.to_json(object_nl: "\n")
  end
end

def write_errata_file(filename, errata, name: '', verbose: false, remove_empty_packages: true)
  data = errata
  # filter empty package-lists
  data = errata.clone.delete_if { |x| x.packages.empty? } if remove_empty_packages

  write_json_file(
    filename,
    data,
    name: name,
    verbose: verbose
  )
end

def get_whitelist(config, name)
  if config.key? 'whitelists'
    whitel = config['whitelists']
    return whitel[name] if whitel.key?(name) && whitel[name].is_a?(Array)
  end
  nil
end

def load_config(filename)
  raise "Config-file #{filename.inspect} not found, please create one from \"config.json.example\"" unless File.exist? filename

  config = DEFAULT_CONF.merge(JSON.parse(File.read(filename)))

  check_config_hash(config, ERRATAPARSER_CONFIG_SCHEMA)
  config
rescue StandardError => e
  fatal("Error loading config: #{e}", 3)
end

if $PROGRAM_NAME == __FILE__
  # parse command-line parameters
  options = parse_commandline

  ## Load config
  fatal("Config-file #{options[:config].inspect} not found, please create one from \"config.json.example\"", 3) unless File.exist? options[:config]
  @config = load_config(options[:config])

  ## Sanity checks
  fatal('No Errata-type specified!', 2, true) unless options.key?(:ubuntu) || options.key?(:debian)

  parser = DebianErrataParser.new(options[:verbose])
  extend Downloader

  if options.key? :debian
    ## Debian
    cfg = @config['debian']
    whitelist_arch = get_whitelist(cfg, 'architectures')
    tempdir = Pathname.new(File.join(@config['tempdir'], 'debian'))
    tempdir.mkpath
    threads = []
    dsa_list = nil
    cve_list = nil
    packages = {}
    metadata = { releases: {} }
    mutex = Mutex.new

    Thread.abort_on_exception = true

    thread_dsa = Thread.new do
      warn 'START  Download DSA-information' if options[:verbose]
      dsa_list = download_file_cached(cfg['dsa_list_url'], File.join(tempdir, 'dsa.list'))
      warn 'FINISH Download DSA-information' if options[:verbose]
    end
    thread_cve = Thread.new do
      warn 'START  Download CVE-information' if options[:verbose]
      cve_file = download_file_cached(cfg['cve_list_url'], File.join(tempdir, 'cve.json'))
      cve_list = JSON.parse(cve_file)
      warn 'FINISH Download CVE-information' if options[:verbose]
    end

    ## Download package-lists
    DebRelease.tempdir = tempdir
    fatal('Config-error missing \'repository\'-section', 4) unless cfg.key?('repository') && cfg['repository'].is_a?(Hash)
    fatal('Config-error \'repo_url\' missing in \'repository\'', 5) unless cfg['repository'].key? 'repo_url'
    fatal('Config-error \'releases\' missing in \'repository\'', 6) unless cfg['repository'].key? 'releases'
    cfg['repository']['releases'].each do |s|
      threads << Thread.new do
        warn "START  Download #{s.inspect} from #{cfg['repository']['repo_url']}" if options[:verbose]
        deb_rel = DebRelease.new(cfg['repository']['repo_url'], s)
        deb_rel.whitelist_comp = get_whitelist(cfg, 'components')
        deb_rel.whitelist_arch = whitelist_arch
        pkgs = deb_rel.all_packages

        # merge package-list
        mutex.synchronize do
          # save Meta-data
          metadata[:releases][deb_rel.release_name] = {
            'architectures': deb_rel.architectures,
            'components': deb_rel.components,
          }

          # merge packages
          pkgs.each do |pkg_name, pkg|
            packages[pkg_name] = {} unless packages.key? pkg_name
            pkg.each do |arch_name, arch|
              packages[pkg_name][arch_name] = [] unless packages[pkg_name].key? arch_name
              packages[pkg_name][arch_name].concat arch
            end
          end
        end
        warn "FINISH Download #{s.inspect} from #{cfg['repository']['repo_url']}" if options[:verbose]
      end
    end

    ## generate Errata
    # wait for DSA-/CVE-list download
    thread_dsa.join
    thread_cve.join
    warn 'START  Generate debian-errata' if options[:verbose]
    errata = parser.gen_debian_errata(DSA.parse_dsa_list_str(dsa_list), cve_list)
    warn 'FINISH Generate debian-errata' if options[:verbose]

    ## add package lists
    # wait for package-list download
    threads.each(&:join)
    # add package-information to errata
    parser.add_binary_packages(
      errata,
      packages,
      releases: get_whitelist(cfg, 'releases'),
      architecture_whitelist: whitelist_arch
    )

    write_errata_file(
      File.join(options[:debian], get_filename(:debian, :errata)),
      errata,
      name: 'debian-errata',
      verbose: options[:verbose]
    )

    if options[:metadata]
      # write Metadata
      write_json_file(
        File.join(options[:debian], get_filename(:debian, :config)),
        metadata,
        name: 'debian-errata-meta',
        verbose: options[:verbose]
      )
    end
  end

  if options.key? :ubuntu
    ## Ubuntu
    require 'bzip2/ffi'
    require 'stringio'

    cfg = @config['ubuntu']
    tempdir = Pathname.new(File.join(@config['tempdir'], 'ubuntu'))
    tempdir.mkpath

    #HTTPDEBUG = options[:verbose]

    warn 'START  Download USN-information' if options[:verbose]
    usn_db = download_file_cached(cfg['usn_list_url'], File.join(tempdir, 'database.json.bz2'))
    warn 'FINISH Download USN-information' if options[:verbose]

    warn 'START  Generate ubuntu-errata' if options[:verbose]
    errata = parser.gen_ubuntu_errata(
      JSON.parse(Bzip2::FFI::Reader.read(StringIO.new(usn_db))),
      get_whitelist(cfg, 'releases'),
      get_whitelist(cfg, 'architectures')
    )
    warn 'FINISH Generate ubuntu-errata' if options[:verbose]

    write_errata_file(
      File.join(options[:ubuntu], get_filename(:ubuntu, :errata)),
      errata,
      name: 'ubuntu-errata',
      verbose: options[:verbose]
    )

    if options[:metadata]
      # write Metadata
      write_json_file(
        File.join(options[:ubuntu], get_filename(:ubuntu, :config)),
        parser.metadata,
        name: 'ubuntu-errata-meta',
        verbose: options[:verbose]
      )
    end
  end

end
