require 'openssl'
require 'base64'
require 'timeout'

$stdout.sync = true
Dir.chdir(File.dirname(__FILE__))

def can_decrypt?(s)
  s = Base64.decode64(s)
  cipher = OpenSSL::Cipher::AES128.new(:CBC)
  cipher.decrypt
  cipher.key = IO.binread('key')
  cipher.iv = s.slice!(0...16)
  cipher.update(s)
  cipher.final
  true
rescue OpenSSL::Cipher::CipherError
  false
end

Timeout::timeout(30) do
  loop do
    s = gets
    break if s.nil?
    p can_decrypt?(s)
  end
end
