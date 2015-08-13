require 'rubame'
require 'openssl'
require 'uri'

module Rubame
  class Server
    def clients
      @clients
    end
  end

  class Client
    class Base64
      def encode(str)
        [str].pack('m')
      end

      def decode(str)
        str.unpack('m').first
      end

      # Encode session cookies as Marshaled Base64 data
      class Marshal < Base64
        def encode(str)
          super(::Marshal.dump(str))
        end

        def decode(str)
          return unless str
          ::Marshal.load(super(str)) rescue nil
        end
      end
    end

    def secure_compare(a, b)
      # from Rack::Utils
      #
      # Constant time string comparison.
      #
      # NOTE: the values compared should be of fixed length, such as strings
      # that have already been processed by HMAC. This should not be used
      # on variable length plaintext strings because it could leak length info
      # via timing attacks.
      return false unless a.bytesize == b.bytesize

      l = a.unpack("C*")

      r, i = 0, -1
      b.each_byte { |v| r |= v ^ l[i+=1] }
      r == 0
    end

    def verify_session_data(session_data)
      # from Rack::Session::Cookie
      digest, session_data = session_data.reverse.split("--", 2)
      digest.reverse! if digest
      session_data.reverse! if session_data
      session_data = nil unless digest_match?(session_data, digest)
      if session_data.nil?
        puts "XXX digest_match failed!"
        false
      else
        puts "XXX session data verified!!!"
        coder = Base64::Marshal.new
        data = coder.decode(session_data) || {}
        puts "XXX data: #{data}"
        true
      end
    end

    def generate_hmac(data, secret)
      OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, secret, data)
    end

    def digest_match?(data, digest)
      return unless data && digest
      secure_compare(digest, generate_hmac(data, ENV['SESSION_SECRET']))
    end
  end
end

server = Rubame::Server.new("0.0.0.0", 8080)

connections = {}

while true
  server.run do |client|
    client.onopen do
      session_data = ''
      puts "client open: socket: #{client.socket} length: #{server.clients.length}"
      puts "-----------------------------------------------------------"
      puts "-                   Handshake                             -"
      puts "-----------------------------------------------------------"
      puts "Version: #{client.handshake.version}"
      client.handshake.headers.each_pair do |key, value|
        if 'cookie' == key
          cookies = value.split
          cookies.each do |c|
            k,v = c.split('=')
            if 'tjs-session' == k
              session_data = v
              puts "session_data : #{session_data}"
            end
          end
        end
      end

      server.close(client) unless client.verify_session_data URI.unescape(session_data)

      puts "-----------------------------------------------------------"
    end

    client.onmessage do |mess|
      puts "message(#{client.socket}): #{mess}"
      server.clients.values.each do |c|
        c.send mess unless c.socket == client.socket
      end
    end

    client.onclose do
      puts "client closed: #{server.clients.length}"
    end
  end
end
