require 'net/https'

HTTPDEBUG = false

# module for cached downloading of files
module Downloader
  def download_file_cached(url, path = nil, force = false)
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
      req.each_header do |h|
        warn "HEADER-REQ: #{h}: #{req[h]}" if HTTPDEBUG
      end
      http.request(req)
    end

    if HTTPDEBUG
      warn res.inspect
      res.each_header do |h|
        warn "HEADER-RES: #{h}: #{res[h]}"
      end
    end

    if res.is_a? Net::HTTPSuccess
      unless path.nil?
        File.open(path, 'w') do |io|
          warn "Save data to #{path}" if HTTPDEBUG
          io.write res.body
        end
      end
      return res.body
    elsif res.is_a? Net::HTTPNotModified
      # Use already downloaded version
      return File.read path
    else
      # raise Exception if response != SUCCESS
      res.value
    end
  end
end
