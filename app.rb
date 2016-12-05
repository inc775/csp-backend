#!/usr/bin/env ruby

require 'sinatra'
require 'json'
require 'mongo'
require 'json/ext'
require 'uri'

configure do
  db = Mongo::Client.new([ ENV['MONGO_PORT_27017_TCP_ADDR'] ], :database => 'csp' )
  set :mongo_db, db[:csp]
  
end

helpers do
  def get_hostname_from_url(url)
    URI.parse(url).host
  end

  def remove_path_from_url(url)
    u = URI.parse(url)
    "#{u.scheme}://#{u.host}:#{u.port}"
  end

  def build_csp(reported_blocks)
    content_security_policy = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; report-uri https://csp.4armed.io/report; object-src 'none'; "
    directives = {}

    reported_blocks.each do |block|
      directive = block['csp-report']['effective-directive']
      blocked_uri = block['csp-report']['blocked-uri']

      if /^http/.match(blocked_uri)
        whitelist_src = remove_path_from_url(blocked_uri)
      elsif /^inline$/.match(blocked_uri)
        whitelist_src = "'unsafe-inline'"
      elsif /^eval$/.match(blocked_uri)
        whitelist_src = "'unsafe-eval'" # don't do this though!
      else
        next
      end

      if directives.has_key? directive
        directives[directive] << whitelist_src
      else
        directives[directive] = [ whitelist_src ]
      end
    end

    directives.each do |dir, value|
      next if value.nil?
      policy = "#{dir} #{value.uniq.join(' ')}"
      content_security_policy << policy + '; '
    end

    { :policy => content_security_policy }.to_json
  end
end

post '/report' do
  content_type :json
  db = settings.mongo_db

  csp_report = JSON.parse(request.body.read.to_s)
  hostname = get_hostname_from_url(csp_report['csp-report']['document-uri'])
  csp_report['csp-report']['document-uri'] = hostname
  begin
    result = db.insert_one csp_report
    "ok"
  rescue Mongo::Error::OperationFailure => e
    logger.debug "[*] #{e.message}"
    "ok"
  end

end

get '/build/:hostname/?' do
  content_type :json

  db = settings.mongo_db
  reported_blocks = db.find({ "csp-report.document-uri": params[:hostname]})
  build_csp reported_blocks
end
