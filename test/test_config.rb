# frozen_string_literal: true

require 'json'
require 'test/unit'

require_relative '../check_config'

class TestDebianErrataConfig < Test::Unit::TestCase
  def test_check_config
    check_config_hash(JSON.parse(File.read(File.join(File.dirname(__FILE__), '../default_config.json'))), ERRATAPARSER_CONFIG_SCHEMA)
  end
end
