require "./ThreatExchange/version.rb"
require "net/http"
require "rest-client"
require "json"
require "pry"

module ThreatExchange
  class Base
    def initialize(config={})
      @access_token = config[:access_token]
      @baseurl = 'https://graph.facebook.com'
    end
  end    

  class Query<Base
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

    def members()
      begin 
        response = RestClient.get "#{@baseurl}/threat_exchange_members/", 
        { params: { access_token: @access_token } }
        return JSON.parse(response)
      rescue => e
        e.response
      end
    end
  end

  class Submission<Base
    def new_connection(data={})
      data[:access_token] = @access_token
      begin
        response = RestClient.post "#{@baseurl}/",
        { params: data }
      rescue => e
        e.response
      end
    end

    def new_ioc(data={})
      data[:access_token] = @access_token
      begin
        response = RestClient.post "#{@baseurl}/",
        { params: data }
      rescue => e
        e.response
      end
    end

    def update_ioc(data={})
      data[:access_token] = @access_token
      begin
        response = RestClient.post "#{@baseurl}/",
        { params: data }
      rescue => e
        e.response
      end
    end

  end
end
binding.pry