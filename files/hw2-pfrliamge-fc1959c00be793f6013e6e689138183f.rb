#!/usr/bin/env ruby

require 'openssl'
require 'timeout'

$stdout.sync = true
Dir.chdir(File.dirname(__FILE__))
flag = IO.read('flag').unpack('H*')[0].to_i(16)
fail unless 2 ** 256 <= flag && flag <= 2 ** 512

Timeout::timeout(30) do
  begin
    puts 'Show me the prime, and I will give you the pfrliamge...?'
    p = gets.to_i
    fail 'Hey it is not a prime!' unless p.to_bn.prime?
    fail 'The prime is too LARGE or too small...' unless 2 ** 100 <= p && p <= 2 ** 200

    puts 'One more magic number please :)'
    x = gets.to_i % p
    fail 'Hacker detected.' unless 2 <= x && x <= p - 2

    puts 'Here is your pfrliamge.'
    puts ((x * flag).to_bn.mod_exp(flag, p) * flag + flag) % p
  rescue RuntimeError => e
    puts "\033[1;31m#{e.message}\033[0m"
  end
end
