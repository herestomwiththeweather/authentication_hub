require 'rubame'

module Rubame
  class Server
    def clients
      @clients
    end
  end
end

server = Rubame::Server.new("0.0.0.0", 8080)

while true
  server.run do |client|
    client.onopen do
      puts "client open: #{server.clients.length}"
    end

    client.onmessage do |mess|
      puts "message: #{mess}"
      server.clients.values.each do |c|
        c.send mess
      end
    end

    client.onclose do
      puts "client closed: #{server.clients.length}"
    end
  end
end
