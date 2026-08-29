# encoding: UTF-8

control 'C-2.19' do
  title 'Ensure that experimental features are not implemented in production'
  desc  "
    Experimental features should not be enabled in production.

    \"Experimental\" is currently a runtime Docker daemon flag rather than being a feature of a separate build. Passing `--experimental` as a runtime flag to the docker daemon activates experimental features. Whilst \"Experimental\" is considered a stable release, it has a number of features which may not have been fully tested and do not guarantee API stability.
  "
  desc  'rationale', "
    Experimental features should not be enabled in production.

    \"Experimental\" is currently a runtime Docker daemon flag rather than being a feature of a separate build. Passing `--experimental` as a runtime flag to the docker daemon activates experimental features. Whilst \"Experimental\" is considered a stable release, it has a number of features which may not have been fully tested and do not guarantee API stability.
  "
  desc  'check', "
    You should run the command below and ensure that the `Experimental` property is set to `false` in the Server section.

    ```
    docker version --format '{{ .Server.Experimental }}'
    ```
  "
  desc  'fix', "
    You should not pass `--experimental` as a runtime parameter to the Docker daemon on production systems.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-7 a']
  tag cci:                   ['CCI-000381']
  tag cis_number:            '2.19'
  tag cis_rid:               '2.19'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0219r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  if input('docker_target_mode') == 'container_only'
    tag implementation_status:  'inherited'
    tag inherited_from:         'aws-shared-responsibility'
    tag attestation_references: ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  else
    tag implementation_status:  'implemented'
  end
  tag exec_validated:           false

  if input('docker_target_mode') == 'container_only'
    uri = input('inherited_evidence_uri', value: '')
    uri = attestation_uri(:leveraged, 'aws-soc2-type2', ext: 'json') if uri.to_s.empty?
    if uri.to_s.empty?
      describe 'AWS shared-responsibility evidence (no leveraged source configured)' do
        skip 'inherited-from-aws: set leveraged_evidence_base / inherited_evidence_uri to the pulled AWS evidence manifest (SOC 2 / FedRAMP / ISO), or `saf attest apply`.'
      end
    else
      doc = document_attestation(uri, max_age_days: input('leveraged_evidence_max_age_days', value: 365))
      describe "AWS shared-responsibility leveraged evidence (#{uri})" do
        it('reachable') { expect(doc.connection_error).to be_nil, "evidence unreachable: #{doc.connection_error}" }
        it('exists') { expect(doc.exists?).to eq(true) }
        it("current") { expect(doc.current?).to eq(true) }
      end
    end
  else
    daemon_json_path = '/etc/docker/daemon.json'
  if file(daemon_json_path).exist?
    describe json(daemon_json_path) do
      its(['experimental']) { should eq false }
    end
  else
    describe 'CIS Docker daemon.json key experimental' do
      skip "host_daemon mode: /etc/docker/daemon.json not present — daemon is running with default flags. Operator confirms `dockerd --experimental` flag from process inventory."
    end
  end
  end
end
