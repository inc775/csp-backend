#!/usr/bin/env ruby

require 'sinatra'
require 'json'
require 'mongo'
require 'json/ext'
require 'uri'
require 'cgi'

configure do
  Mongo::Logger.logger.level = ::Logger::FATAL
  db = Mongo::Client.new([ ENV['MONGO_PORT_27017_TCP_ADDR'] ], :database => 'csp' )
  set :mongo_db, db[:csp]
  
end

helpers do
  def get_hostname_from_url(url)
    u = URI.parse(url)
    if [80, 443].include? u.port
      u.host
    else
      "#{u.host}:#{u.port}"
    end
  end

  def remove_path_from_url(url)
    u = URI.parse(url)
    "#{u.scheme}://#{u.host}:#{u.port}"
  end

  def build_csp(reported_blocks, unsafe=false)
    content_security_policy = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; report-uri #{request.scheme}://#{request.host_with_port}/report; "
    directives = {}

    reported_blocks.each do |block|
      directive = block['csp-report']['effective-directive']
      blocked_uri = block['csp-report']['blocked-uri']

      if directive.nil?
        # some reports don't contain effective-directive, don't know why
        directive = block['csp-report']['violated-directive'].split(/\s/)[0]
        next if directive.nil?
      end

      if /^http/.match(blocked_uri)
        whitelist_src = remove_path_from_url(blocked_uri)
      end

      if /^self$/.match(blocked_uri)
        whitelist_src = 'self'
      end

      /^(inline)|^(eval)/.match(blocked_uri) do |match|
        whitelist_src = "'unsafe-#{match[0]}'" if unsafe === "1"
      end

      next if whitelist_src.nil?

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

get '/policy/:hostname/?' do
  content_type :json

  db = settings.mongo_db
  reported_blocks = db.find({ "csp-report.document-uri": CGI.unescape(params[:hostname])})
  build_csp reported_blocks, params[:unsafe]
end

delete '/policy/:hostname/?' do
  content_type :json

  db = settings.mongo_db
  db.delete_many({ "csp-report.document-uri": CGI.unescape(params[:hostname])}) unless params[:hostname].nil?
end