require "./ThreatExchange/version.rb"
require "net/http"
require "rest-client"
require "json"
require "pry"

module ThreatExchange
  class Query

    def initialize(config={})
      @access_token = config[:access_token]
      @baseurl = 'https://graph.facebook.com'
    end

    def malware_analyses(filter={})
      filter[:access_token] = @access_token
      begin 
        response = RestClient.get "#{@baseurl}/malware_analyses", 
          { params: filter } 
        return JSON.parse(response)
      rescue => e
        e.response
      end
    end

    def threat_indicators(filter={})
      filter[:access_token] = @access_token
      begin
        response = RestClient.get "#{@baseurl}/threat_indicators", 
          { params: filter } 
        return JSON.parse(response)
        e.response
      end
    end

    def malware_objects(filter={})
      filter[:access_token] = @access_token
      begin 
        response = RestClient.get "#{@baseurl}/", 
          { params: filter } 
        return JSON.parse(response)
      rescue => e
        e.response
      end
    end

    def connections(filter={})
      filter[:access_token] = @access_token
      begin 
        response = RestClient.get "#{@baseurl}/#{filter[:id]}/#{filter[:connection]}/", 
        { params: { access_token: @access_token } }
        return JSON.parse(response)
      rescue => e
        e.response
      end
    end

    def new_ioc(data={})
      data[:access_token] = @access_token
      begin
        response = RestClient.post "",
        { params: data }
      rescue => e
        e.response
      end
    end

    def update_ioc(data={})
      data[:access_token] = @access_token
      begin
        response = RestClient.post "",
        { params: data }
      rescue => e
        e.response
      end
    end

    def set_connection(data={})
      data[:access_token] = @access_token
      begin
        response = RestClient.post "",
        { params: data }
      rescue => e
        e.response
      end
    end
 end
end
binding.pry