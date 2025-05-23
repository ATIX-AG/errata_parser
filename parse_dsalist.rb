# frozen_string_literal: true

require 'json'

REGEX_1ST_LINE = /^\[(?<date>[^\]]+)\]\s*(?<ident>[A-z0-9-]+)\s*(?<package>\S+)\s*-*\s*(?<typ>.*)$/
REGEX_CVE_LINE = /\s+{(?<cves>[^}]*)}/
REGEX_REL_LINE = /\s+\[(?<release>[^\]]*)\]\s*-\s*(?<package>\S+)\s*(?<version>\S*)/
REGEX_NOT_LINE = /\s+NOTE:/

# Base-Parser Exception
class ParserException < RuntimeError
  def initialize(lnum = -1, line = nil, msg = 'ParserException', critical: true)
    super("at #{lnum}: #{msg} (#{line})")
    @lnum = lnum
    @line = line
    @critical = critical
  end
end

# critical Parser-Error
class ParserError < ParserException
  def initialize(lnum, line, msg)
    super
    @critical = true
  end
end

# uncritical ParserError
class ParserWarning < ParserException
  def initialize(lnum, line, msg)
    super
    @critical = false
  end
end

# {'a'=>1, 'b'=>2} to {:a=>1, :b=>2}
# keys must be symbols for usage as named method-parameters
def symbolize_hash_keys(hsh)
  return nil if hsh.nil?

  res = {}
  hsh.each do |k, v|
    res[k.to_sym] = v
  end
  res
end

# "smart" list of DSAs
class DSAList < Array
  def initialize
    @opt_ignore_empty_cve = true
    super
  end

  def secure_push(item)
    return unless item.is_a? DSA
    return if @opt_ignore_empty_cve && item.cve_empty?

    push item
  end
end

# DebianSecurityAdvisory
class DSA
  PARSE_DSA_LIST_OPTIONS_DEFAULTS = {
    ignore_empty_cve: true
  }.freeze

  attr_reader :date, :id, :type, :package, :versions, :cve

  def initialize(date:, ident:, typ:, package:)
    @date = date
    @id = ident
    @type = typ
    @package = package
    @versions = {}
    @cve = []
  end

  def add_cve(cve_numbers)
    @cve = Array.new(cve_numbers)
  end

  def cve_empty?
    (@cve.nil? || @cve.empty?)
  end

  def add_release(release:, package:, version:)
    @versions[release] = {} unless @versions.key? release
    @versions[release][package] = version
  end

  def pp
    puts("#{@id} from #{@date} for #{@package}")
    puts("  CVE: #{@cve}")
    @versions.each_key do |rel|
      puts("\t#{rel}")
      rel_dict = @versions[rel]
      rel_dict.each_key do |p|
        puts("\t\t#{p} #{rel_dict[p]}")
      end
    end
  end

  # for conversion to JSON
  def to_h
    {
      'name' => @id,
      'date' => @date,
      'type' => @type,
      'package' => @package,
      'cve' => @cve,
      'versions' => @versions
    }
  end

  def to_json(*options)
    to_h.to_json(*options)
  end

  # Recreate data from original DSA-list file
  # param release_filter Array of relase_name String, e.g. `[ 'bullseye', 'stretch' ]`
  # returns String e.g.:
  # [11 Dec 2021] DSA-5020-1 apache-log4j2 - security update
  # \t{CVE-2021-44228}
  # \t[buster] - apache-log4j2 2.15.0-1~deb10u1
  # \t[bullseye] - apache-log4j2 2.15.0-1~deb11u1
  def to_orig(release_filter=nil)
    e = StringIO.new
    e.puts "[#{@date}] #{@id} #{@package} - #{@type}"
    e.puts "\t{#{@cve.join(' ')}}"

    versions = @versions
    # filter releases and return nil if no remaining releases
    if release_filter.respond_to? :include?
      versions = versions.select { |v| release_filter.include?(v) }
      return nil if versions.empty?
    end

    versions.each do |rel, packages|
      packages.each do |name, version|
        e.puts "\t[#{rel}] - #{name} #{version}"
      end
    end
    e.string
  end

  ## Class methods expects IO
  def self.parse_dsa_list_str(string)
    parse_dsa_list(StringIO.new(string))
  end

  def self.parse_dsa_list(io)
    raise "requires IO object; got #{io.class.name}" unless io.respond_to? :each_line

    dsa = nil
    dsa_list = DSAList.new
    i = 0

    io.each_line do |line|
      i += 1
      res1 = REGEX_1ST_LINE.match(line)
      if res1
        dsa_list.secure_push dsa
        dsa = DSA.new(**symbolize_hash_keys(res1.named_captures))
      elsif dsa
        res = REGEX_REL_LINE.match(line)
        if res
          dsa.add_release(**symbolize_hash_keys(res.named_captures))
          next
        end
        res = REGEX_CVE_LINE.match(line)
        if res
          dsa.add_cve(res[:cves].split) unless res[:cves].empty?
          next
        end
        if REGEX_NOT_LINE.match(line)
          # ignore 'NOTE:' lines
          next
        end

        raise ParserWarning.new(i, line, 'Unknown Line in DSA')

      else
        raise ParserWarning.new(i, line, 'Unknown Line')
      end
    rescue ParserException => e
      raise if e.critical

      warn(e)
    end

    dsa_list.secure_push dsa
  end
end

if $PROGRAM_NAME == __FILE__
  dsa_list = nil
  File.open('test/data/dsa.list', 'r') do |f|
    dsa_list = DSA.parse_dsa_list(f)
  end

  if ENV['FILTERED_ORIGINAL']
    release_whitelist = ['bullseye']
    dsa_list.each do |dsa|
      s = dsa.to_orig(release_whitelist)
      puts s unless s.nil?
    end
  else
    puts JSON.generate(dsa_list)
  end
end
