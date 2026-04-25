# -*- encoding: utf-8 -*-
# stub: yara-normalize 1.0.0 ruby lib

# yara-normalize.gemspec
Gem::Specification.new do |s|
  s.name                  = "yara-normalize"
  s.version               = "1.0.0"
  s.authors               = ["Chris Lee"]
  s.email                 = ["rubygems@chrislee.dhs.org"]

  s.summary               = "Normalizes Yara signatures into a repeatable hash even when non-transforming changes are made."
  s.description           = "Provides normalization and hashing utilities for Yara rule comparisons."
  s.license               = "MIT"
  s.homepage              = "https://github.com/chrislee35/yara-normalize"
  s.required_ruby_version = ">= 3.0"

  s.files                 = Dir.glob("lib/**/*") + ["LICENSE.txt", "README.rdoc", "bin/yaratool"]
  s.executables           = ["yaratool"]
  s.require_paths         = ["lib"]

  # Runtime dependencies (if any, currently none)
  # s.add_dependency "yara", ">= 4.0"  # example if you had one

  # Development dependencies
  s.add_development_dependency "test-unit", "~> 3.6"
  s.add_development_dependency "shoulda", "~> 4"
  s.add_development_dependency "rspec", "~> 3.12"
  s.add_development_dependency "rake", "~> 13.3"
  s.add_development_dependency "bundler", "~> 2.7"
  s.add_development_dependency "rdoc", "~> 6.6"
end

