require_relative '../gen_errata'
require_relative '../parse_dsalist'
require 'json'
require 'yaml'
require 'test/unit'

class TestDebianErrata < Test::Unit::TestCase
  def test_gen_debian_errata
    original_path = "#{File.dirname(__FILE__)}/data/debian.yaml"
    dsa_list_path = "#{File.dirname(__FILE__)}/data/dsa.list"
    cve_json_path = "#{File.dirname(__FILE__)}/data/cve.json"
    pkg_json_path = "#{File.dirname(__FILE__)}/data/packages_everything_debian.json"
    parser = DebianErrataParser.new

    errata = parser.gen_debian_errata(
      DSA.parse_dsa_list_str(File.read(dsa_list_path)),
      JSON.parse(File.read(cve_json_path))
    )
    parser.add_binary_packages_from_file(errata, pkg_json_path, ['stretch'], ['amd64'])

    assert_instance_of(Array, errata)

    hsh = {}
    errata.each do |erratum|
      # remove Errata without packages
      next if erratum.packages.empty?

      hsh[erratum.name] = erratum.to_h
      erratum.packages.each do |p|
        assert_equal('stretch', p['release'], "Offending data was in #{erratum.name}: #{p.inspect}")
        assert_include(['amd64', 'all'], p['architecture'], "Offending data was in #{erratum.name}: #{p.inspect}")
      end
    end
    generated = hsh

    original = YAML.load_file(original_path)

    assert_equal(original.length, generated.keys.length)

    original.each do |v|
      name = v['name']
      #FIXME for some reasons ruby insists that assert only takes one argument
      assert(generated.key?(name)) # , "Erratum #{name.inspect} not found")
      assert_equal(v, generated[name], "Erratum #{name.inspect} does not match")
    end
  end

  def test_gen_ubuntu_errata
    require 'bzip2/ffi'
    original_path = "#{File.dirname(__FILE__)}/data/ubuntu.yaml"
    usn_list_path = "#{File.dirname(__FILE__)}/data/database.json.bz2"
    pkg_json_path = "#{File.dirname(__FILE__)}/data/packages_everything_ubuntu.json"
    parser = DebianErrataParser.new

    packages = JSON.parse(File.read(pkg_json_path))

    f = File.open usn_list_path, 'rb'
    errata = parser.gen_ubuntu_errata(
      JSON.parse(
        Bzip2::FFI::Reader.read(f)
      ),
      ['bionic'],
      ['amd64'],
      packages
    )
    f.close
    assert_instance_of(Array, errata)

    hsh = {}
    errata.each do |erratum|
      # remove Errata without packages
      next if erratum.packages.empty?

      hsh[erratum.name] = erratum.to_h
      erratum.packages.each do |p|
        assert_equal('bionic', p['release'], "Offending data was in #{erratum.name}: #{p.inspect}")
        assert_include(['amd64', 'all'], p['architecture'], "Offending data was in #{erratum.name}: #{p.inspect}")
      end
    end
    generated = hsh

    original = YAML.load_file(original_path)

    assert_equal(original.length, generated.keys.length)

    original.each do |v|
      name = v['name']
      #FIXME for some reasons ruby insists that assert only takes one argument
      assert(generated.key?(name)) # , "Erratum #{name.inspect} not found")
      assert_equal(v, generated[name], "Erratum #{name.inspect} does not match")
    end
  end
end
