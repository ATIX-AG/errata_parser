#!/usr/bin/env ruby

require 'net/http'
require 'feedjira'

class LatestErratum
  ACCEPTED_CONTENT_TYPES = [
    'application/rss+xml',
    'text/xml',
  ]
  def initialize(url)
    res = Net::HTTP.get_response(URI(url))
    unless ACCEPTED_CONTENT_TYPES.include? res['content-type'].split(';').first
      raise "Unsupported content-type: #{res['content-type']}"
    end
    @feed = Feedjira.parse(res.body)
  end
  def latest
    @feed.entries.first
  end
  def latest_published
    latest.published
  end
  def latest_id
    latest.title.split.first
  end
end

class LatestDsaErratum < LatestErratum
  def initialize()
    super('https://www.debian.org/security/dsa')
  end
end

class LatestDlaErratum < LatestErratum
  def initialize()
    super('https://www.debian.org/lts/security/dla')
  end
end

class LatestUsnErratum < LatestErratum
  def initialize()
    super('https://ubuntu.com/security/notices/rss.xml')
  end
end

dsa = LatestDsaErratum.new
dla = LatestDlaErratum.new
usn = LatestUsnErratum.new
puts "Latest DLA Erratum #{dla.latest_id} (#{dla.latest_published})"
puts "Latest DSA Erratum #{dsa.latest_id} (#{dsa.latest_published})"
puts "Latest USN Erratum #{usn.latest_id} (#{usn.latest_published})"
