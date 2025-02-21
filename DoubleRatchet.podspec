Pod::Spec.new do |s|

  s.name          = "DoubleRatchet"
  s.version       = "2.0.1"
  s.summary       = "Double Ratchet protocol."
  s.platform      = :ios, "12.0"
  s.swift_version = "5.0"

  s.homepage      = "http://ticeapp.com"

  s.author        = { "TICE Software UG (haftungsbeschränkt)" => "contact@ticeapp.com" }
  s.source        = { :git => "https://github.com/dpasirst/DoubleRatchet.git", :tag => "#{s.version}" }
  s.license      = { :type => 'MIT' }

  s.source_files  = "Sources/**/*"

  s.dependency "Sodium"
  s.dependency "HKDF"
  s.dependency "Logging"

  s.user_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64' }
  s.pod_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64' }

end
