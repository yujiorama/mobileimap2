# coding: utf-8
require 'erb'
require 'json'

require "oauth"
require "oauth/consumer"
require 'sinatra'

require './gmail_client'

enable :sessions

before do
  session[:oauth] ||= {}
  consumer_key = ENV["CONSUMER_KEY"] || ENV["consumer_key"] || "anonymous"
  consumer_secret = ENV["CONSUMER_SECRET"] || ENV["consumer_secret"] || "anonymous"
  
  @consumer ||= OAuth::Consumer.new(consumer_key, consumer_secret,
                                    :site => "https://www.google.com",
                                    :request_token_path => '/accounts/OAuthGetRequestToken?scope=https://mail.google.com/%20https://www.googleapis.com/auth/userinfo%23email',
                                    :access_token_path => '/accounts/OAuthGetAccessToken',
                                    :authorize_path => '/accounts/OAuthAuthorizeToken'
                                    )
  
  if !session[:oauth][:request_token].nil? && !session[:oauth][:request_token_secret].nil?
    @request_token = OAuth::RequestToken.new(@consumer, session[:oauth][:request_token], session[:oauth][:request_token_secret])
  end

  if !session[:oauth][:access_token].nil? && !session[:oauth][:access_token_secret].nil?
    @access_token = OAuth::AccessToken.new(@consumer, session[:oauth][:access_token], session[:oauth][:access_token_secret])
  end
end

include ERB::Util

get '/' do
  if @access_token
    response = @access_token.get('https://www.googleapis.com/userinfo/email?alt=json')
    email = response.is_a?(Net::HTTPSuccess) ? JSON.parse(response.body)['data']['email'] : "guest@gmail.com"
    client = GmailClient.new(:xoauth, email,
                             :consumer_key    => 'anonymous',
                             :consumer_secret => 'anonymous',
                             :consumer_token  => session[:oauth][:access_token],
                             :consumer_secret => session[:oauth][:access_token_secret])
    @mails = client.list_new_mail
  end
  erb :index
end

get "/request" do
  redirect "/logout" unless @consumer
  @request_token = @consumer.get_request_token(:oauth_callback => "#{request.scheme}://#{request.host}:#{request.port}/auth")
  session[:oauth][:request_token] = @request_token.token
  session[:oauth][:request_token_secret] = @request_token.secret
  logger.info @request_token.authorize_url if @request_token
  redirect @request_token.authorize_url
end

get "/auth" do
  @access_token = @request_token.get_access_token :oauth_verifier => params[:oauth_verifier]
  session[:oauth][:access_token] = @access_token.token
  session[:oauth][:access_token_secret] = @access_token.secret
  redirect "/"
end

def get_or_post(path, opts={}, &block)
  get(path, opts, &block)
  post(path, opts, &block)
end

get_or_post "/logout" do
  session[:oauth] = {}
  redirect "/"
end

