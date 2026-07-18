# frozen_string_literal: true

require 'json'
require 'minitest/autorun'
require 'rack/mock'

require_relative 'market_stream'

class MarketStreamAPIAuthTest < Minitest::Test
  AUTH_ENV_KEYS = %w[
    MARKET_STREAM_API_AUTH_REQUIRED
    API_AUTH_REQUIRED
    MARKET_STREAM_API_TOKEN
    API_AUTH_TOKEN
  ].freeze

  def setup
    @saved_env = AUTH_ENV_KEYS.each_with_object({}) { |key, env| env[key] = ENV[key] }
    AUTH_ENV_KEYS.each { |key| ENV.delete(key) }
    $start_time = Time.now.utc
    $message_count = 0
  end

  def teardown
    @saved_env.each do |key, value|
      value.nil? ? ENV.delete(key) : ENV[key] = value
    end
  end

  def request(path, headers = {})
    Rack::MockRequest.new(MarketStreamAPI).get(path, headers)
  end

  def test_enabled_auth_accepts_valid_bearer_token
    ENV['MARKET_STREAM_API_AUTH_REQUIRED'] = 'true'
    ENV['MARKET_STREAM_API_TOKEN'] = 'valid-token'

    response = request('/api/v2/status', 'HTTP_AUTHORIZATION' => 'Bearer valid-token')
    body = JSON.parse(response.body)

    assert_equal 200, response.status
    assert_equal 'market-stream', body['service']
  end

  def test_enabled_auth_rejects_missing_credentials
    ENV['MARKET_STREAM_API_AUTH_REQUIRED'] = 'true'
    ENV['MARKET_STREAM_API_TOKEN'] = 'valid-token'

    response = request('/api/v2/status')
    body = JSON.parse(response.body)

    assert_equal 401, response.status
    assert_equal 'Unauthorized', body['error']
  end

  def test_enabled_auth_rejects_invalid_credentials
    ENV['MARKET_STREAM_API_AUTH_REQUIRED'] = 'true'
    ENV['MARKET_STREAM_API_TOKEN'] = 'valid-token'

    response = request('/api/v2/market/ticks/BTC-USD', 'HTTP_X_MARKET_STREAM_TOKEN' => 'wrong-token')
    body = JSON.parse(response.body)

    assert_equal 401, response.status
    assert_equal 'Unauthorized', body['error']
  end

  def test_disabled_auth_allows_protected_endpoint_without_credentials
    ENV['MARKET_STREAM_API_AUTH_REQUIRED'] = 'false'
    ENV['MARKET_STREAM_API_TOKEN'] = 'valid-token'

    response = request('/api/v2/market/ticks/BTC-USD')
    body = JSON.parse(response.body)

    assert_equal 200, response.status
    assert_equal 'BTC-USD', body['instrument']
  end

  def test_health_endpoint_remains_public_when_auth_is_enabled
    ENV['MARKET_STREAM_API_AUTH_REQUIRED'] = 'true'
    ENV['MARKET_STREAM_API_TOKEN'] = 'valid-token'

    response = request('/health')
    body = JSON.parse(response.body)

    assert_equal 200, response.status
    assert_equal 'OK', body['status']
  end
end
