#!/usr/bin/env ruby

require 'openssl'
require 'timeout'

$stdout.sync = true
Dir.chdir(File.dirname(__FILE__))

def encrypt(bits, m)
  p = OpenSSL::BN.generate_prime(bits, false)
  q = OpenSSL::BN.generate_prime(bits, false)
  n = p * q
  fail if m >= n
  puts n, m ** 3 % n, (m + 1) ** 3 % n
end

Timeout::timeout(60) do
  1.upto(10) do |i|
    m = rand(2 ** (128 * i - 2))
    puts "== Level #{i} =="
    encrypt(64 * i, m)
    exit if gets.to_i != m
  end
  puts "== Flag =="
  encrypt(1024, IO.read('flag').unpack('H*')[0].to_i(16))
end
