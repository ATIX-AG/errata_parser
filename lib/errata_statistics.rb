# frozen_string_literal: true

require 'json/streamer'
require 'date'
require 'yaml'
require 'json'

# Class to analyze errata.json files created by parser
# collects statistics and can be used to search for specific errata
class ErrataStatistics
  attr_reader :pkg_errata, :per_release, :errata_file, :avg_rel_errata

  CHUNK_SIZE = 4096
  STAT_HASH_INIT = {
    avg: 0,
    max: nil,
    min: nil,
    max_erratum: nil,
    latest_erratum: nil,
    latest_erratum_date: nil,
    num_errata: 0
  }.freeze

  def initialize(errata_file)
    @pkg_errata = STAT_HASH_INIT.clone
    @per_release = {}
    @avg_rel_errata = 0
    @errata_file = errata_file
  end

  def moving_average(avg, new, total)
    (new.to_f + (avg * (total - 1))) / total
    # new.to_f/total + avg*(1-1.0/total)
  end

  def calc_stats_data(stat_hash, packages, erratum)
    pkgs = packages.length
    stat_hash[:num_errata] += 1
    stat_hash[:avg] = moving_average(stat_hash[:avg], pkgs, stat_hash[:num_errata])
    if stat_hash[:max].nil? || pkgs > stat_hash[:max]
      stat_hash[:max] = pkgs
      stat_hash[:max_erratum] = erratum['name']
    end
    stat_hash[:min] = pkgs if stat_hash[:min].nil? || pkgs < stat_hash[:min]
  end

  def latest_erratum(stat_hash, erratum)
    date = Date.parse(erratum['issued'])
    return unless stat_hash[:latest_erratum_date].nil? || stat_hash[:latest_erratum_date] < date

    stat_hash[:latest_erratum] = erratum['name']
    stat_hash[:latest_erratum_date] = date
  end

  def print_stats(stat_hash, indent=0)
    s = ' ' * indent
    puts "#{s}Errata: #{stat_hash[:num_errata]}"
    puts "#{s}Newest: #{stat_hash[:latest_erratum]} (#{stat_hash[:latest_erratum_date]})"
    puts "#{s}Packages:"
    puts "#{s}  average per Erratum: #{stat_hash[:avg].round(2)}"
    puts "#{s}  max per Erratum: #{stat_hash[:max]} (#{stat_hash[:max_erratum]})"
    puts "#{s}  min per Erratum: #{stat_hash[:min]}"
  end

  def print_all
    print_stats(pkg_errata)

    per_release.each do |release, stats|
      puts "#{release.inspect}:"
      print_stats(stats, 2)
    end
  end

  def to_h
    per_release.merge({ 'all' => pkg_errata })
  end

  def to_yaml
    to_h.to_yaml
  end

  def to_json(*_args)
    to_h.to_json
  end

  def each(&)
    File.open(errata_file, 'r') do |file|
      streamer = Json::Streamer.parser(file_io: file, chunk_size: CHUNK_SIZE)
      streamer.get(nesting_level: 1, &)
    end
  end

  # returns Array of errata whose names are in query_name (Array)
  def search_for_name(query_name)
    query = query_name.clone
    res = []
    each do |erratum|
      next unless query_name.include? erratum['name']

      res << erratum
      query.delete erratum['name']

      break if query.empty?
    end
    res
  end

  def calculate
    each do |erratum|
      packages = erratum['packages']
      releases = packages.map { |p| p['release'] }.uniq

      # Per Release data
      releases.each do |release|
        per_release[release] = STAT_HASH_INIT.clone unless per_release.key? release

        pkgs = packages.select { |pkg| pkg['release'] == release }
        h = per_release[release]

        # Packages per errata
        calc_stats_data(h, pkgs, erratum)
        # Latest erratum
        latest_erratum(h, erratum)
      end

      # Packages per errata
      calc_stats_data(pkg_errata, packages, erratum)

      # Average number of releases per erratum
      @avg_rel_errata = moving_average(avg_rel_errata, releases.length, pkg_errata[:num_errata])

      # Latest erratum
      latest_erratum(pkg_errata, erratum)
    end
  end
end
