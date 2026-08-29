# encoding: UTF-8

control 'C-3.11' do
  title 'Ensure that Docker server certificate file ownership is set to root:root'
  desc  "
    You should verify that the Docker server certificate file (the file that is passed along with the `--tlscert` parameter) is individual owned and group owned by `root`.

    The Docker server certificate file should be protected from any tampering. It is used to authenticate the Docker server based on the given server certificate. It must therefore be individually owned and group owned by `root` to prevent modification by less privileged users.
  "
  desc  'rationale', "
    You should verify that the Docker server certificate file (the file that is passed along with the `--tlscert` parameter) is individual owned and group owned by `root`.

    The Docker server certificate file should be protected from any tampering. It is used to authenticate the Docker server based on the given server certificate. It must therefore be individually owned and group owned by `root` to prevent modification by less privileged users.
  "
  desc  'check', "
    You should execute the command below to verify that the Docker server certificate file is individually owned and group owned by `root`:
    ```
    stat -c %U:%G | grep -v root:root
    ```
    The above command should return no results.
  "
  desc  'fix', "
    You should run the following command:
    ```
    chown root:root ```
    This sets the individual ownership and the group ownership for the Docker server certificate file to `root`.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 c']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-IAM-SUS']
  tag nist_r4:               ['AC-2 c']
  tag cci:                   ['CCI-002113']
  tag cis_number:            '3.11'
  tag cis_rid:               '3.11'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0311r1_rule'
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
      skip "Requires manual review and attestation provided for this control (Docker server certificate path is daemon.json-driven)"
    end
  end
end
