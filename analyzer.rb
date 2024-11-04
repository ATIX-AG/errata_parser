#!/usr/bin/env ruby

# frozen_string_literal: true

require_relative 'lib/errata_statistics'

output_type = nil

output_type = ARGV.shift.slice(2..).to_sym if ARGV[0].start_with? '--'

stats = ErrataStatistics.new ARGV[0]
stats.calculate

case output_type
when :yaml then puts stats.to_yaml
when :json then puts stats.to_json
else stats.print_all
end
