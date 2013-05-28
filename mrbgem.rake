MRuby::Gem::Specification.new('mruby-sha2') do |spec|
  spec.license = 'MIT'
  spec.authors = 'h2so5'
  spec.cc.flags << '-DENABLE_FILE_DIGEST'
end
