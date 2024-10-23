# frozen_string_literal: true

require 'faraday'
require 'date'

# API doc: https://ubuntu.com/security/api/docs
class UbuntuSecurityApi
  attr_accessor :retry

  def initialize(opts={})
    @base_url = 'https://ubuntu.com'
    @retry = opts[:retry]
  end

  def yesterdays_erratum(release=nil)
    # ASSUMPTION: among the latest 5 USNs there should be at least one older than one day
    res = latest_errata(release, 5).select { |usn| Date.parse(usn['published']) < Date.today }

    raise 'Could not find USN older than one day among the newest 5' if res.empty?

    res.first
  end

  def latest_errata(release=nil, limit=nil)
    opts = {
      order: 'newest',
      show_hidden: false
    }
    opts[:release] = release unless release.nil?

    opts[:limit] = limit unless limit.nil?

    attempt = @retry
    begin
      res = conn.get('/security/notices.json', opts)
      res.body['notices']
    rescue Faraday::ServerError
      raise if attempt.nil? || attempt.zero?

      attempt -= 1
      retry
    end
  end

  def latest_erratum(release=nil)
    latest_errata(release, 1).first
  end

  private

  def conn
    @conn ||= Faraday.new(
      url: @base_url,
      headers: { 'Content-Type' => 'application/json' }
    ) do |builder|
      # Sets the Content-Type header to application/json on each request.
      # Also, if the request body is a Hash, it will automatically be encoded as JSON.
      builder.request :json

      # Parses JSON response bodies.
      # If the response body is not valid JSON, it will raise a Faraday::ParsingError.
      builder.response :json

      # Raises an error on 4xx and 5xx responses.
      builder.response :raise_error

      # Logs requests and responses.
      # By default, it only logs the request method and URL, and the request/response headers.
      # builder.response :logger
    end
  end
end
