#!/usr/bin/env ruby


require 'json'
require 'yaml'
require 'date'

require_relative 'parse_dsalist'


URGENCY_PRIO = [
  "not yet assigned",
  "low",
  "medium",
  "high"
]
SCOPE_PRIO = [
  "local",
  "remote"
]


def get_max_prio_idx(map, old, new)
  old ||= -1
  idx = map.index { |x| new =~ /#{x}/ }
  if idx.nil?
    old
  else
    [ old, idx ].max
  end
end


def gen_debian_errata(dsa_list, cve_list)
  errata = Hash.new

  dsa_list.each do |dsa|
    dsa = dsa.to_h if dsa.kind_of? DSA
    erratum = Hash.new()
    erratum["title"] = "#{dsa["package"]} -- #{dsa["type"]}"
    #erratum["issued"] = Date.strptime(dsa["date"], "%d %b %Y")
    erratum["issued"] = dsa["date"]
    erratum["cves"] = dsa["cve"] if dsa.has_key? "cve"
    erratum["affected_source_package"] = dsa["package"]

    description = []
    packages = {}

    if dsa.has_key? "cve" and dsa["cve"].length > 0
      cves = dsa["cve"].map{ |c| cve_list[dsa["package"]]&.fetch(c, nil)&.merge("name" => c) }
      cves.delete_if { |cve| cve.nil? }

      debianbugs = Array.new
      scope_idx = -1
      severity_idx = -1
      cves.each do |cve|
        debianbugs << cve["debianbug"] if cve.has_key? "debianbug"
        scope_idx = get_max_prio_idx(SCOPE_PRIO, scope_idx, cve.fetch("scope", nil))
        description << cve["description"]

        cve["releases"].each do |rel,data|
          if data["status"] == "resolved"
            packages[rel] = { :version => nil } unless packages.has_key? rel

            packages[rel] = {
              :version => data["fixed_version"]
            }

            severity_idx = get_max_prio_idx(URGENCY_PRIO, severity_idx, data["urgency"])
          end
        end

        erratum["scope"] = SCOPE_PRIO[scope_idx]
        erratum["severity"] = URGENCY_PRIO[severity_idx]

      end

      erratum["packages"] = []
      packages.each do |rel,data|
        erratum["packages"].append({
          "name" => dsa["package"],
          "version" => data[:version],
          "release" => rel
        })
      end
      erratum["dbts_bugs"] = debianbugs unless debianbugs.empty?
      erratum["description"] = description.delete_if{ |d| d.nil? or d.empty? }.join("\n\n")

    end

=begin
    if cve_list.has_key? dsa["package"]
      cves = cve_list[dsa["package"]].select{ |k,v| dsa["cve"].include? k }
      warn "#{dsa["name"]}: #{dsa["package"]}"
      warn cves.inspect
    end
=end
    errata[dsa["name"]] = erratum
    #warn erratum.inspect
    #break
  end
  errata
end

def download_file_cached(url, path, force=false)
  require 'net/https'
  uri = URI(url)
  fs = File.stat path if File.exist? path

  req = Net::HTTP::Get.new(uri)
  # try to use cached version if possible
  if fs and not force
    req['If-Modified-Since'] = fs.mtime.utc.strftime "%a, %d %b %Y %T GMT"
  end

  res = Net::HTTP.start(uri.hostname, uri.port,
      :use_ssl => uri.scheme == 'https') { |http|
    http.request(req)
  }

  warn res.inspect

  if res.is_a? Net::HTTPSuccess
    open path, 'w' do |io|
      io.write res.body
    end
    return res.body
  elsif res.is_a? Net::HTTPNotModified
    # Use already downloaded version
    return File.read path
  else
    # raise Exception if response != SUCCESS
    res.value()
  end
end

#for testing
def add_binary_packages(errata, package_json_path)
  packages = JSON.parse(File.read(package_json_path))

  errata.each do |name,erratum|
    new = []
    erratum["packages"].each do |p|
      # FIXME hardcoded release
      release = "stretch"
      if p["release"] == release
        if packages.has_key? p["name"]
          packages[p["name"]].each do |name,version|
            if version != p["version"]
              warn "#{name} has different version in package.json: #{p["version"]} => #{version}"
            end
            new.append({
              "name" => name,
              "version" => version,
              "release" => release
            })
          end
        end
      end
      erratum["packages"] = new
    end unless erratum["packages"].nil?

  end
end

if __FILE__ == $0
  dsa_list = download_file_cached("https://salsa.debian.org/security-tracker-team/security-tracker/raw/master/data/DSA/list", "test_data/dsa.list")
  cve_file = download_file_cached("https://security-tracker.debian.org/tracker/data/json", "test_data/cve.json")
  #warn File.read("test_data/cve.json")[0,255]
  errata = gen_debian_errata(DSA.parse_dsa_list_str(dsa_list), JSON.parse(cve_file))
  add_binary_packages(errata, "packages.json")

  # filter empty package-lists
  errata.delete_if { |k,x| x["packages"].nil? or x["packages"].empty? }
  puts errata.to_yaml
end

