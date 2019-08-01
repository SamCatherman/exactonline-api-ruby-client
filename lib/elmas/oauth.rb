# frozen_string_literal: true

require "mechanize"
require "uri"
require "json"

require File.expand_path("../utils", __FILE__)
require File.expand_path("../response", __FILE__)

# from https://developers.exactonline.com/#Example retrieve access token.html

# This whole to_s is going to be replaced due to Exact Online's new policies.
# https://support.exactonline.com/community/s/knowledge-base#All-All-HNO-Concept-general-security-gen-auth-totpc

module Elmas
  # rubocop:disable Metrics/ModuleLength
  module OAuth
    def authorize(user_name, password, options = {})
      warn "[DEPRECATION] `authorize` is deprecated. Please implement your own authorization methods instead."
      agent = Mechanize.new

      login(agent, user_name, password, options)
      allow_access(agent)

      code = URI.unescape(agent.page.uri.query.split("=").last)
      OauthResponse.new(get_access_token(code))
    end

    def refresh_authorization
      warn "[DEPRECATION] `refresh_authorization` is deprecated. Please implement your own authorization methods instead."
      puts "refresh_token: #{refresh_token}"
      puts "get_refresh_token: #{get_refresh_token(refresh_token).inspect}"
      puts "get_refresh_token class: #{get_refresh_token(refresh_token).class}"
      puts "get_refresh_token access: #{get_refresh_token(refresh_token).access_token}"
      puts "get_refresh_token refresh: #{get_refresh_token(refresh_token).refresh_token}"
      OauthResponse.new(get_refresh_token(refresh_token)).tap do |response|
        puts "inside oauth response block: #{response.inspect}"
        Elmas.configure do |config|
          config.access_token = response.access_token
          config.refresh_token = response.refresh_token
        end
      end
    end

    def authorized?
      # Do a test call, return false if 401 or any error code
      get("/Current/Me", no_division: true)
    rescue BadRequestException
      Elmas.error "Not yet authorized"
      return false
    end

    def authorize_division
      get("/Current/Me", no_division: true).results.first.current_division
    end

    def auto_authorize
      warn "[DEPRECATION] `auto_authorize` is deprecated. Please implement your own authorization methods instead."
      Elmas.configure do |config|
        config.redirect_uri = ENV["REDIRECT_URI"]
        config.client_id = ENV["CLIENT_ID"]
        config.client_secret = ENV["CLIENT_SECRET"]
        config.access_token = Elmas.authorize(ENV["EXACT_USER_NAME"], ENV["EXACT_PASSWORD"]).access_token
        config.division = Elmas.authorize_division
      end
    end

    # Return URL for OAuth authorization
    def authorize_url(options = {})
      options[:response_type] ||= "code"
      options[:redirect_uri] ||= redirect_uri
      params = authorization_params.merge(options)
      uri = URI("#{base_url}/api/oauth2/auth/")
      uri.query = URI.encode_www_form(params)
      uri.to_s
    end

    # Return an access token from authorization
    def get_access_token(code, _options = {})
      conn = Faraday.new(url: base_url) do |faraday|
        faraday.request :url_encoded
        faraday.adapter Faraday.default_adapter
      end
      params = access_token_params(code)
      conn.post do |req|
        req.url "/api/oauth2/token"
        req.body = params
        req.headers["Accept"] = "application/json"
      end
    end

    # Return an access token from authorization via refresh token
    def get_refresh_token(refresh_token)
      conn = Faraday.new(url: config[:base_url]) do |faraday|
        faraday.request :url_encoded
        faraday.adapter Faraday.default_adapter
      end

      params = refresh_access_token_params(refresh_token)

      conn.post do |req|
        req.url "/api/oauth2/token"
        req.body = params
        req.headers["Accept"] = "application/json"
        req.headers["Content-Type"] = "application/x-www-form-urlencoded"
      end
    end

    private

    def login(agent, user_name, password, options)
      # Login
      agent.get(authorize_url(options)) do |page|
        form = page.forms.first
        form["UserNameField"] = user_name
        form["PasswordField"] = password
        form.click_button
      end
    end

    def allow_access(agent)
      return if agent.page.uri.to_s.include?("getpostman")
      return if agent.page.uri.to_s.include?(redirect_uri)
      form = agent.page.form_with(id: "PublicOAuth2Form")
      button = form.button_with(id: "AllowButton")
      agent.submit(form, button)
    end

    def authorization_params
      {
        client_id: client_id
      }
    end

    def access_token_params(code)
      {
        client_id: client_id,
        client_secret: client_secret,
        grant_type: "authorization_code",
        code: code,
        redirect_uri: redirect_uri
      }
    end

    def refresh_access_token_params(code)
      {
        client_id: client_id,
        client_secret: client_secret,
        grant_type: "refresh_token",
        refresh_token: code
      }
    end
  end
end

module Elmas
  class OauthResponse < Response
    def body
      puts "OauthResponse Class - response: #{@response.inspect}"
      puts "OauthResponse Class - response.body.class: #{@response.body.class}"
      puts "OauthResponse Class - response.body parsed: #{JSON.parse(@response.body.to_s)}"
      
      JSON.parse(@response.body)
    end

    def access_token
      body["access_token"]
    end

    def division
      body["division"]
    end

    def refresh_token
      body["refresh_token"]
    end
  end
end
