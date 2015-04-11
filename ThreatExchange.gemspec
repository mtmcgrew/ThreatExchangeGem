# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ThreatExchange/lib/version'

Gem::Specification.new do |spec|
  spec.name          = "ThreatExchange"
  spec.version       = ThreatExchange::Version 
  spec.authors       = ["Maus Stearns"]
  spec.email         = ["maus@fb.com"]
  spec.summary       = %q{Gem abstraction for Facebooks ThreatExchange}
  spec.description   = %q{Wrapper for rest-client wtih Facebooks Graph API}
  spec.homepage      = "https://threatexchange.fb.com/"
  spec.license       = "BSD"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.6"
  spec.add_development_dependency "rake"
  spec.add_dependency "rest-client"
end
