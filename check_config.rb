# frozen_string_literal: true

##
# ErrataParser config schema
#
ERRATAPARSER_ALIASES_SCHEMA = { type: Hash, mandatory: false, child: {
  'releases' => { type: Hash, mandatory: false, child: {
    type: Array, mandatory: true, child: { type: String, mandatory: true }
  } }
} }.freeze
ERRATAPARSER_WHITELIST_SCHEMA = { type: Hash, mandatory: false, child: {
  'releases' => { type: Array, mandatory: false, child: {
    type: String, mandatory: true
  } },
  'components' => { type: Array, mandatory: false, child: {
    type: String, mandatory: true
  } },
  'architectures' => { type: Array, mandatory: false, child: {
    type: String, mandatory: true
  } }
} }.freeze
ERRATAPARSER_REPOSITORY_SCHEMA = { type: Hash, mandatory: true, child: {
  'repo_url' => { type: String, mandatory: true },
  'credentials' => { type: Hash, mandatory: false, child: {
    'user' => { type: String, mandatory: true },
    'pass' => { type: String, mandatory: true }
  } },
  'releases' => { type: Array, mandatory: true, child: {
    type: String, mandatory: true
  } }
} }.freeze
ERRATAPARSER_CONFIG_SCHEMA = {
  'tempdir' => { type: String, mandatory: false },
  'debian' => { type: Hash, mandatory: false, child: {
    'dsa_list_url' => { type: String, mandatory: true },
    'dla_list_url' => { type: String, mandatory: false },
    'cve_list_url' => { type: String, mandatory: true },
    'repositories' => {
      type: Array, mandatory: true, child: ERRATAPARSER_REPOSITORY_SCHEMA
    },
    'aliases' => ERRATAPARSER_ALIASES_SCHEMA,
    'whitelists' => ERRATAPARSER_WHITELIST_SCHEMA,
    'special-kernel-pkg-collection' => { type: Array, mandatory: false, child: {
      type: String, mandatory: true
    } }
  } },
  'ubuntu' => { type: Hash, mandatory: false, child: {
    'usn_list_url' => { type: String, mandatory: true },
    'repository' => ERRATAPARSER_REPOSITORY_SCHEMA,
    'aliases' => ERRATAPARSER_ALIASES_SCHEMA,
    'whitelists' => ERRATAPARSER_WHITELIST_SCHEMA
  } },
  'ubuntu-esm' => { type: Hash, mandatory: false, child: {
    'usn_list_url' => { type: String, mandatory: true },
    'repository' => ERRATAPARSER_REPOSITORY_SCHEMA,
    'aliases' => ERRATAPARSER_ALIASES_SCHEMA,
    'whitelists' => ERRATAPARSER_WHITELIST_SCHEMA
  } }
}.freeze

# takes config (cfg) as a ruby-hash and a schema-hash like above.
# problems will be reported by throwing exceptions
def check_config_hash(cfg, schema, path='')
  if schema.key?(:type)
    # Hash with not custom keys of fixed schema
    cfg.each do |k, v|
      local_path = "#{path}.#{k}"
      raise "#{local_path}: has type #{v.class.name} but should be #{schema[:type]}" if v.class != schema[:type]

      check_config_child(v, schema, local_path) if schema.key?(:child)
    end

  else
    keylist = cfg.keys
    # iterate all possible entries
    schema.each do |k, v|
      local_path = "#{path}.#{k}"
      raise "#{path}: Mandatory key #{k.inspect} not found in config" if v[:mandatory] && !cfg.key?(k)

      next unless cfg.key? k

      raise "#{local_path}: has type #{cfg[k].class.name} but should be #{v[:type]}" if cfg[k].class != v[:type]

      check_config_child(cfg[k], v, local_path) if v.key?(:child)
      keylist.delete(k)
    end
    raise "Found unknown keys (not defined in schema) at #{path.inspect}: #{keylist.join(', ')}" unless keylist.empty?
  end
end

def check_config_array(cfg, schema, path='')
  child_type = schema[:type]
  raise "#{path}: List is not allowed to be empty" if schema[:mandatory] && cfg.empty?

  cfg.each_index do |i|
    raise "#{path}: Item##{i} has type #{cfg[i].class.name} but should be #{child_type}" if cfg[i].class != child_type

    check_config_child(cfg[i], schema, path) if schema.key?(:child)
  end
end

def check_config_child(cfg, schema, path='')
  # recursively check Hashes
  check_config_hash(cfg, schema[:child], path) if schema[:type] == Hash

  # check Array elements
  check_config_array(cfg, schema[:child], path) if schema[:type] == Array
end

if $PROGRAM_NAME == __FILE__
  require 'json'

  config_path = ARGV[0] || 'default_config.json'

  check_config_hash(JSON.parse(File.read(config_path)), ERRATAPARSER_CONFIG_SCHEMA)
end
