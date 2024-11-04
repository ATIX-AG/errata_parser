# frozen_string_literal: true

require 'net/http'
require 'feedjira'

# module to inject #erratum_id into Feedjira's feed-entries
module ErrataEntryUtilities
  def erratum_id
    title.split.first.slice(/[\w-]+/)
  end
end
Feedjira::Parser::RSSEntry.include ErrataEntryUtilities

# Generic class to extract information from Debian/Ubuntu 'errata' RSS-feeds (security announcements)
class LatestErratum
  ACCEPTED_CONTENT_TYPES = [
    'application/rss+xml',
    'text/xml'
  ].freeze
  def initialize(url)
    res = Net::HTTP.get_response(URI(url))
    raise "Unsupported content-type: #{res['content-type']}" unless ACCEPTED_CONTENT_TYPES.include? res['content-type'].split(';').first

    @feed = Feedjira.parse(res.body)
  end

  def latest
    entries.first
  end

  def latest_published
    latest.published
  end

  def latest_id
    latest.erratum_id
  end

  def since_yesterday
    @feed.entries.select { |entry| entry.published + 1 >= Time.now }
  end

  # returns array of the latest 'num' feed-entries
  # TODO: assumes the feed is sorted by date
  def recent(num=1)
    entries.slice(0, num)
  end

  def entries
    @feed.entries
  end
end

# read and parse latest Debian Security Announcements (DSA) RSS-feed
class LatestDsaErratum < LatestErratum
  def initialize
    super('https://www.debian.org/security/dsa')
  end
end

# read and parse latest Debian LTS Security Announcements (DLA) RSS-feed
class LatestDlaErratum < LatestErratum
  def initialize
    super('https://www.debian.org/lts/security/dla')
  end
end

# read and parse latest Ubuntu Security Notices (USN) RSS-feed
class LatestUsnErratum < LatestErratum
  def initialize
    super('https://ubuntu.com/security/notices/rss.xml')
  end
end
