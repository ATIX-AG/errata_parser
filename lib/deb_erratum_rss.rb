require 'net/http'
require 'feedjira'

module ErrataEntries
  def errata_ids
    map{ |e| e.title.split.first.slice(/[\w-]+/) }
  end
end

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

  def since_yesterday
    @feed.entries.select{ |entry| entry.published+1 >= Time.now }
  end

  # returns array of the latest 'n' feed-entries
  # TODO: assumes the feed is sorted by date
  def recent(n=1)
    @feed.entries.slice(0, n).extend ErrataEntries
  end

  def entries
    @feed.entries
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
