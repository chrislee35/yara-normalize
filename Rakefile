# encoding: utf-8

require 'rubygems'
require 'bundler'
begin
  Bundler.setup(:default, :development)
rescue Bundler::BundlerError => e
  $stderr.puts e.message
  $stderr.puts "Run `bundle install` to install missing gems"
  exit e.status_code
end
require 'rake'

require 'jeweler'
Jeweler::Tasks.new do |gem|
  # gem is a Gem::Specification... see http://docs.rubygems.org/read/chapter/20 for more options
  gem.name = "yara-normalize"
  gem.homepage = "http://github.com/chrislee35/yara-normalize"
  gem.license = "MIT"
  gem.summary = %Q{Normalizes Yara Signatures into a repeatable hash even when non-transforming changes are made}
  gem.description = %Q{To enable consistent comparisons between yara rules (signature), a uniform hashing standard was needed.}
  gem.email = "rubygems@chrislee.dhs.org"
  gem.authors = ["chrislee35"]
  #gem.signing_key = "#{File.dirname(__FILE__)}/../gem-private_key.pem"
  #gem.cert_chain  = ["#{File.dirname(__FILE__)}/../gem-public_cert.pem"]
end
Jeweler::RubygemsDotOrgTasks.new

require 'rake/testtask'
Rake::TestTask.new(:test) do |test|
  test.libs << 'test'
  test.pattern = FileList['test/test*.rb']
  test.verbose = true
end

task :default => :test

require 'rdoc/task'
Rake::RDocTask.new do |rdoc|
  version = File.exist?('VERSION') ? File.read('VERSION') : ""

  rdoc.rdoc_dir = 'rdoc'
  rdoc.title = "yara-normalize #{version}"
  rdoc.rdoc_files.include('README*')
  rdoc.rdoc_files.include('lib/**/*.rb')
end
