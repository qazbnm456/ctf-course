require 'base64'
require 'json'
require 'openssl'
require 'timeout'

$stdout.sync = true
Dir.chdir(File.dirname(__FILE__))

cipher = OpenSSL::Cipher::AES128.new('ECB')
cipher.encrypt
cipher.key = IO.binread('key')

Timeout::timeout(30) do
  print 'username: '
  username = gets.chomp
  print 'password: '
  password = gets.chomp

  uid = username.bytes.inject(:+)
  flag = IO.read('flag')
  user_data = "uid: #{uid}, password: #{password}, flag: #{flag}"
  cookie = Base64.encode64(cipher.update(user_data) + cipher.final).delete("\n")
  puts "Cookie: #{cookie}"
end
