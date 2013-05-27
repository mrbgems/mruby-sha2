##
# SHA2 Test

plaintext = 'The quick brown fox jumps over the lazy dog'
sha256 = 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592'
sha384 = 'ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a50' + 
         '9cb1e5dc1e85a941bbee3d7f2afbc9b1'
sha512 = '07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb64' + 
         '2e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6'

assert('Digest::SHA256.hexdigest') do
  Digest::SHA256.hexdigest(plaintext) == sha256
end

assert('Digest::SHA384.hexdigest') do
  Digest::SHA384.hexdigest(plaintext) == sha384
end

assert('Digest::SHA512.hexdigest') do
  Digest::SHA512.hexdigest(plaintext) == sha512
end
