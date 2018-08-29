#!/usr/bin/env ruby


require 'json'
require 'yaml'
require 'date'


URGENCY_PRIO = [
  "not yet assigned",
  "low",
  "medium",
  "high"
]


class Erratum < Hash
  def scope=(s)
    case self.fetch("scope", nil)
    when nil
      self["scope"] = s unless s.nil?
    when "local"
      self["scope"] = s if s =~ /remote/i
    end
  end
end


def gen_errata(dsa_list, cve_list)
  errata = Hash.new

  dsa_list.each do |dsa|
    erratum = Erratum.new()
    erratum["title"] = "#{dsa["package"]} -- #{dsa["type"]}"
    erratum["issued"] = Date.strptime(dsa["date"], "%d %b %Y")
    erratum["cves"] = dsa["cve"] if dsa.has_key? "cve"
    erratum["affected_source_package"] = dsa["package"]

    description = []
    packages = {}
    severity = 0

    if dsa.has_key? "cve" and dsa["cve"].length > 0
      cves = dsa["cve"].map{ |c| cve_list[dsa["package"]]&.fetch(c, nil)&.merge("name" => c) }
      cves.delete_if { |cve| cve.nil? }

      debianbugs = Array.new
      scope = nil
      cves.each do |cve|
        debianbugs << cve["debianbug"] if cve.has_key? "debianbug"
        erratum.scope = cve.fetch("scope", nil)
        description << cve["description"]

        cve["releases"].each do |rel,data|
          if data["status"] == "resolved"
            packages[rel] = { :version => nil } unless packages.has_key? rel

            packages[rel] = {
              :version => data["fixed_version"]
            }

            severity_local = URGENCY_PRIO.index { |x| data["urgency"] =~ /#{x}/ }
            severity = [ severity, severity_local ].max unless severity_local.nil?
          end
        end


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
      erratum["severity"] = URGENCY_PRIO[severity]

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
  elsif res.is_a? Net::HTTPNotModified
    # Use already downloaded version
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
  download_file_cached("https://security-tracker.debian.org/tracker/data/json", "test_data/cve.json")
  warn File.read("test_data/cve.json")[0,255]
  #errata = gen_errata(JSON.parse(File.read("test.json")), JSON.parse(File.read("test_data/cve.json")))
  #add_binary_packages(errata, "packages.json")
  #puts errata.to_yaml
end

