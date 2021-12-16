require 'json'

packageJson = JSON.parse(File.read('package.json'))
name = packageJson["name"]
version = packageJson["version"]
description = packageJson["description"]
homepage = packageJson["homepage"]
license = packageJson["license"]
author = packageJson["author"]
repository = packageJson["repository"]["url"]
iqVersion = version.split('-').first

# min cocoapods version 1.8.4
system("mkdir -p #{__dir__}/../../.temp")
zipfile = "#{__dir__}/../../.temp/#{packageJson["name"]}.zip"
system("rm -rf #{zipfile} && cd ios && zip -r #{zipfile} . > /dev/null")

Pod::Spec.new do |s|
	s.name           = name
	s.version        = version
	s.description    = description
	s.summary        = description
	s.homepage       = homepage
	s.license        = license
	s.authors        = author
    s.source = { :http => "file://#{zipfile}"}
	s.platform       = :ios, "9.0"
	s.preserve_paths = 'README.md', 'package.json', '*.js'
	s.source_files   = '**/*.{h,m}'

	s.dependency 'React'
end
