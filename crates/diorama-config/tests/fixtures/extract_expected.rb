# Independent conversion of captured Go YAML, never using the Rust decoder/validator.
require 'yaml'
require 'json'
base = File.dirname(__FILE__)
%w[config-command yaml-reference semantic-reference map-reference layers-reference].each do |name|
  fixture = JSON.parse(File.read(File.join(base, "#{name}.json")))
  fixture['cases'].each do |test|
    text = name == 'config-command' ? test.dig('expect', 'stdout_equals') : test['stdout']
    next if text.nil? || text.empty?
    expected = YAML.safe_load(text)
    # These five Go omitempty fields represent zero values; no runtime normalization.
    expected['kubernetes']['nodeName'] ||= ''
    expected['runtime']['containerMode'] = nil unless expected['runtime'].key?('containerMode')
    expected['kubernetes']['apiServer']['extraSANs'] ||= nil
    expected['kubernetes']['kubelet']['systemReserved'] ||= nil
    expected['kubernetes']['kubelet']['cpuManager']['policyOptions'] ||= nil
    test['expected_typed'] = expected
  end
  File.write(File.join(base, "#{name}.json"), JSON.pretty_generate(fixture) + "\n")
end
