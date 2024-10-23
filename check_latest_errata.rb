#!/usr/bin/env ruby

# frozen_string_literal: true

require 'optparse'
require_relative 'lib/deb_erratum_rss'
require_relative 'lib/errata_statistics'

# get Ubuntu-ESM errata for specific releases from USN-API instead of RSS-feed,
# because RSS-feed probably does not hold latest errata for Ubuntu-ESM releases
USE_USN_API = true

search_num = 5
warn_num = 3
crit_num = 1
@debug = false
@res = {}
@perf_data = []
@long_text = []

def eval_result(id, found, searched, warn, crit)
  @res[id] = case found.length
             when (crit + 1)..warn then :warning
             when 0..crit then :critical
             end

  # see https://nagios-plugins.org/doc/guidelines.html#AEN200
  @perf_data << "'#{id}'=#{found.length};#{warn};#{crit};0;#{searched.length}"

  @long_text << if found.length == searched.length
                  "#{id} errata up-to-date"
                else
                  "#{id} errata miss #{(searched - found).join(', ')}"
                end
end

optparse = OptionParser.new do |opts|
  opts.banner = 'Usage: check_latest_errata.rb [options] <path>'

  opts.on('-q', '--query-num NUM', Integer, "Number of errata that should be queried (default: #{search_num})") do |v|
    search_num = v
  end
  opts.on('-w', '--warn NUM', Integer, "Threshold for warning (default: #{warn_num})") do |v|
    raise 'warning threshold must be positive' if v.negative?

    warn_num = v
  end
  opts.on('-c', '--crit NUM', Integer, "Threshold for critical (default: #{crit_num})") do |v|
    raise 'critical threshold must be positive' if v.negative?

    crit_num = v
  end
  opts.on('-d', '--[no-]debug', 'Debug output for testing') do |v|
    @debug = v
  end
end
optparse.parse!

path = ARGV.pop
unless path
  warn optparse
  exit 3
end

raise 'critical threshold must be smaller than query-num' if crit_num > search_num
raise 'warning threshold must be smaller than query-num' if warn_num > search_num
raise 'critical threshold must be smaller than warning threshold' if crit_num > warn_num
raise 'errata file path is not a directory' unless File.directory? path

begin
  # Debian
  dsa = LatestDsaErratum.new
  dla = LatestDlaErratum.new
  warn "Latest DLA Erratum #{dla.latest_id} (#{dla.latest_published})" if @debug
  warn "Latest DSA Erratum #{dsa.latest_id} (#{dsa.latest_published})" if @debug
  deb_stats = ErrataStatistics.new File.join(path, 'debian_errata.json')
  search_ids = dla.recent(search_num).map(&:erratum_id)
  search_ids += dsa.recent(search_num).map(&:erratum_id)
  found = deb_stats.search_for_name(search_ids).map { |x| x['name'] }
  warn "Searched for #{search_ids}\nFound #{found.inspect}" if @debug
  eval_result('debian', found, search_ids, warn_num * 2, crit_num * 2)

  # Ubuntu
  usn = LatestUsnErratum.new
  warn "Latest USN Erratum #{usn.latest_id} (#{usn.latest_published})" if @debug
  stats = ErrataStatistics.new File.join(path, 'ubuntu_errata.json')
  search_ids = usn.recent(search_num).map(&:erratum_id)
  warn "Search for #{search_ids}" if @debug
  found = stats.search_for_name(search_ids).map { |x| x['name'] }
  warn "Found #{found.inspect}" if @debug
  eval_result('ubuntu', found, search_ids, warn_num, crit_num)

  # Ubuntu-ESM
  search_ids = if USE_USN_API
                 require_relative 'lib/ubuntu_security_api'
                 esm_releases = [
                   'xenial',
                   'bionic'
                 ]
                 usa = UbuntuSecurityApi.new(retry: 3)
                 esm_releases.map do |rel|
                   usa.latest_errata(rel, search_num).map { |notice| notice['id'] }
                 end.flatten.uniq
               else
                 usn = LatestUsnErratum.new
                 warn "Latest USN Erratum #{usn.latest_id} (#{usn.latest_published})" if @debug
                 usn.recent(search_num * 2).map(&:erratum_id)
               end
  stats = ErrataStatistics.new File.join(path, 'ubuntu-esm_errata.json')
  # Look for the doubled amount since it is less likely that USNs are found for ESM releases
  warn "Search for #{search_ids}" if @debug
  found = stats.search_for_name(search_ids).map { |x| x['name'] }
  warn "Found #{found.map { |e| e['name'] }.inspect}" if @debug
  factor = search_ids.length / search_num
  eval_result('ubuntu-esm', found, search_ids, warn_num * factor, crit_num * factor)

  out = StringIO.new
  out << 'ERRATA '
  critical = @res.map { |_k, v| v == :critical }.first
  warning = @res.map { |_k, v| v == :warning }.first
  out << if critical
           "CRIT #{critical} misses errata"
         elsif warning
           "WARN #{warning} misses errata"
         else
           'OK'
         end
  out << '; |' << @perf_data.shift << "\n"
  out << @long_text.join(";\n")
  out << '; | '
  out << @perf_data.join("\n")

  puts out.string
rescue StandardError => e
  puts "ERRATA EXCEPTION #{e}"
  exit 3
end

exit 2 if @res.values.include? :critical
exit 1 if @res.values.include? :warning
