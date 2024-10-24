#!/usr/bin/env ruby

require_relative 'lib/deb_erratum_rss'
require_relative 'lib/errata_statistics'

# look at the latest 'search_num' errata in the RSS feeds
search_num = 5
WARN_NUM = 3
CRIT_NUM = 1
DEBUG = false

@res = {}
@perf_data = []
@long_text = []

def eval_result(id, found, searched, w=WARN_NUM, c=CRIT_NUM)
  @res[id] = case found.length
             when (c + 1)..w then :warning
             when 0..c then :critical
             end

  # see https://nagios-plugins.org/doc/guidelines.html#AEN200
  @perf_data << "'#{id}'=#{found.length};#{w};#{c};0;#{searched.length}"

  @long_text << if found.length == searched.length
                  "#{id} errata up-to-date"
                else
                  "#{id} errata miss #{(found - searched).join(', ')}"
                end
end

begin
  # Debian
  dsa = LatestDsaErratum.new
  dla = LatestDlaErratum.new
  warn "Latest DLA Erratum #{dla.latest_id} (#{dla.latest_published})" if DEBUG
  warn "Latest DSA Erratum #{dsa.latest_id} (#{dsa.latest_published})" if DEBUG
  deb_stats = ErrataStatistics.new 'debian_errata.json'
  search_ids = dla.recent(search_num).errata_ids
  search_ids += dsa.recent(search_num).errata_ids
  found = deb_stats.search_for_name(search_ids).map { |x| x['name'] }
  warn "Searched for #{search_ids}\nFound #{found.inspect}" if DEBUG
  eval_result('debian', found, search_ids, WARN_NUM * 2, CRIT_NUM * 2)

  # Ubuntu
  usn = LatestUsnErratum.new
  warn "Latest USN Erratum #{usn.latest_id} (#{usn.latest_published})" if DEBUG
  stats = ErrataStatistics.new 'ubuntu_errata.json'
  search_ids = usn.recent(search_num).errata_ids
  warn "Search for #{search_ids}" if DEBUG
  found = stats.search_for_name(search_ids).map { |x| x['name'] }
  warn "Found #{found.inspect}" if DEBUG
  eval_result('ubuntu', found, search_ids)

  # Ubuntu-ESM
  search_ids = if false
                 usn = LatestUsnErratum.new
                 warn "Latest USN Erratum #{usn.latest_id} (#{usn.latest_published})" if DEBUG
                 usn.recent(search_num * 2).errata_ids
               else
                 require_relative 'lib/ubuntu_security_api'
                 esm_releases = [
                   'xenial',
                   'bionic'
                 ]
                 usa = UbuntuSecurityApi.new(retry: 3)
                 esm_releases.map do |rel|
                   usa.latest_errata(rel, search_num).map { |notice| notice['id'] }
                 end.flatten.uniq
               end
  stats = ErrataStatistics.new 'ubuntu-esm_errata.json'
  # Look for the doubled amount since it is less likely that USNs are found for ESM releases
  warn "Search for #{search_ids}" if DEBUG
  found = stats.search_for_name(search_ids).map { |x| x['name'] }
  warn "Found #{found.map { |e| e['name'] }.inspect}" if DEBUG
  factor = search_ids.length / search_num
  eval_result('ubuntu-esm', found, search_ids, WARN_NUM * factor, CRIT_NUM * factor)


  out = StringIO.new
  out << 'ERRATA '
  out << if critical = @res.map { |_k, v| v == :critical }.first
           "CRIT #{critical} misses errata"
         elsif warning = @res.map { |_k, v| v == :warning }.first
           "WARN #{warning} misses errata"
         else
           'OK'
         end
  out << '; |' << @perf_data.shift << "\n"
  out << @long_text.join(";\n")
  out << '; | '
  out << @perf_data.join("\n")

  puts out.string

rescue Exception => e
  puts "ERRATA EXCEPTION #{e}"
  exit 3
end

exit 2 if @res.values.include? :critical
exit 1 if @res.values.include? :warning
