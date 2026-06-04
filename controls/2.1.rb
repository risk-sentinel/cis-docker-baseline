# encoding: UTF-8

control 'C-2.1' do
  title 'Run the Docker daemon as a non-root user, if possible'
  desc  "
    Rootless mode executes the Docker daemon and containers inside a user namespace, with both the daemon and the container are running without root privileges.

    Rootless mode allows running the Docker daemon and containers as a non-root user to mitigate potential vulnerabilities in the daemon and the container runtime.
  "
  desc  'rationale', "
    Rootless mode executes the Docker daemon and containers inside a user namespace, with both the daemon and the container are running without root privileges.

    Rootless mode allows running the Docker daemon and containers as a non-root user to mitigate potential vulnerabilities in the daemon and the container runtime.
  "
  desc  'check', "
    Running the following command will show any running `dockerd` processes and which user that is managing the daemon.

    ```
    ps -fe | grep 'dockerd'
    ```
  "
  desc  'fix', "
    Follow the current Docker documentation on how to install the Docker daemon as a non-root user.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 a']
  tag cci:                   ['CCI-000364']
  tag cis_number:            '2.1'
  tag cis_rid:               '2.1'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0201r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  if input('docker_target_mode') == 'container_only'
    tag implementation_status:  'inherited'
    tag inherited_from:         'aws-shared-responsibility'
    tag attestation_references: ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  else
    tag implementation_status:  'alternative'
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
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (\"if possible\" — rootless Docker is an opt-in topology; CIS recognises operators may run rootful with mitigations)"
    end
  end
end
