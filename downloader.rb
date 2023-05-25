# frozen_string_literal: true

require 'net/https'
require 'date'

HTTPDEBUG = false

# module for cached downloading of files
module Downloader
  MAXREDIRECTHOPS = 5

  def download_file_cached(url, path = nil, force = false, maxhop = MAXREDIRECTHOPS)
    uri = URI(url)
    fs = File.stat path if path && File.exist?(path)

    req = Net::HTTP::Get.new(uri)
    # try to use cached version if possible
    req['If-Modified-Since'] = fs.mtime.to_datetime.httpdate if fs && !force

    res = Net::HTTP.start(
      uri.hostname,
      uri.port,
      use_ssl: uri.scheme == 'https'
    ) do |http|
      if HTTPDEBUG
        warn "DOWNLOAD #{uri}"
        req.each_header do |h|
          warn "HEADER-REQ: #{h}: #{req[h]}"
        end
      end
      http.request(req)
    end

    if HTTPDEBUG
      warn res.inspect
      res.each_header do |h|
        warn "HEADER-RES: #{h}: #{res[h]}"
      end
    end

    case res
    when Net::HTTPSuccess
      mode = 'wb'
      body = res.body
      # check for content type; use 'wb' for images
      if res.content_type =~ /application\json/ ||
         res.content_type =~ /text/
        mode = 'w'
        body = body.to_s.force_encoding(Encoding::UTF_8)
      end
      unless path.nil?
        File.open(path, mode) do |io|
          warn "Save data to #{path}" if HTTPDEBUG
          io.write body
        end
      end
      body
    when Net::HTTPNotModified
      # Use already downloaded version
      File.read path
    when Net::HTTPFound
      # Redirect!
      warn "REDIRECTed to #{res['location'].inspect}"
      raise "Max redirect-depth reached (#{MAXREDIRECTHOPS} hops)" if maxhop.zero?

      download_file_cached(res['location'], path, force, maxhop - 1)
    else
      # raise Exception if response != SUCCESS
      res.value
    end
  end
end
