require 'json'
require 'test/unit'

require_relative '../check_config'

class TestDebianErrataConfig < Test::Unit::TestCase
  def test_check_config
    check_config_hash(JSON.parse(File.read(File.join(File.dirname(__FILE__), '../config.json.example'))), ERRATAPARSER_CONFIG_SCHEMA)
  end
end
