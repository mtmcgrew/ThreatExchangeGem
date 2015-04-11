require "ThreatExchange/version"
require "rest-client"
require "json"

module ThreatExchange

  class Client
    attr_accessor :access_token
    def initialize(access_token=nil)
      @access_token = access_token
      @baseurl = 'https://graph.facebook.com'
    end

    def malware_analyses(filter={})
      filter[:access_token] = @access_token
      begin 
        response = RestClient.get "#{@baseurl}/malware_analyses", 
        { params: filter } 
        result = JSON.parse(response)
        return result['data']
      rescue => e
        e.response
      end
    end

    def threat_indicators(filter={})
      filter[:access_token] = @access_token
      begin
        response = RestClient.get "#{@baseurl}/threat_indicators", 
        { params: filter } 
        result = JSON.parse(response)
        return result['data']
        e.response
      end
    end

    def malware_objects(filter={})
      filter[:access_token] = @access_token
      begin 
        response = RestClient.get "#{@baseurl}/", 
        { params: filter } 
        result = JSON.parse(response)
        return result['data']
      rescue => e
        e.response
      end
    end

    def connections(filter={})
      begin 
        response = RestClient.get "#{@baseurl}/#{filter[:id]}/#{filter[:connection]}/", 
        { params: { access_token: @access_token } }
        result = JSON.parse(response)
        return result['data']
      rescue => e
        e.response
      end
    end

    def members()
      begin 
        response = RestClient.get "#{@baseurl}/threat_exchange_members/", 
        { params: { access_token: @access_token } }
        return JSON.parse(response)
      rescue => e
        e.response
      end
    end

    def new_relation(data={})
      data[:access_token] = @access_token
      begin
        response = RestClient.post "#{@baseurl}/#{data[:id]}/related/",
        { params: data }
      rescue => e
        e.response
      end
    end

    def remove_relation(data={})
      data[:access_token] = @access_token
      begin
        response = RestClient.delete "#{@baseurl}/#{data[:id]}/related/?related_id=#{data[:related_id]}"
      rescue => e
        e.response
      end
    end

    def new_ioc(data={})
      data[:access_token] = @access_token
      begin
        response = RestClient.post "#{@baseurl}/threat_indicators/",
        { params: data }
      rescue => e
        e.response
      end
    end

    def update_ioc(data={})
      data[:access_token] = @access_token
      begin
        response = RestClient.post "#{@baseurl}/#{data[:id]}",
        { params: data }
      rescue => e
        e.response
      end
    end

  end
end
