# encoding: UTF-8

control 'C-3.8' do
  title 'Ensure that registry certificate file permissions are set to 444 or more restrictively'
  desc  "
    You should verify that all the registry certificate files (usually found under `/etc/docker/certs.d/ ` directory) have permissions of `444` or are set more restrictively.

    Note that, by default, this directory might not exist if no registry certificate files are in place.

    The `/etc/docker/certs.d/ ` directory contains Docker registry certificates. These certificate files must have permissions of `444`or more restrictive permissions in order to ensure that unprivileged users do not have full access to them..
  "
  desc  'rationale', "
    You should verify that all the registry certificate files (usually found under `/etc/docker/certs.d/ ` directory) have permissions of `444` or are set more restrictively.

    Note that, by default, this directory might not exist if no registry certificate files are in place.

    The `/etc/docker/certs.d/ ` directory contains Docker registry certificates. These certificate files must have permissions of `444`or more restrictive permissions in order to ensure that unprivileged users do not have full access to them..
  "
  desc  'check', "
    You should execute the command below to verify that registry certificate files have permissions of `444` or are more restrictively set.
    ```
    find /etc/docker/certs.d/ -type f -exec stat -c \"%a %n\" {} \\;
    ```
  "
  desc  'fix', "
    You should execute the following command:
    ```
    find /etc/docker/certs.d/ -type f -exec chmod 0444 {} \\; 
    ```
    This would set the permissions for the registry certificate files to `444`.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '3.8'
  tag cis_rid:               '3.8'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0308r1_rule'
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
      skip "Requires manual review and attestation provided for this control (registry certificate paths are deployment-specific)"
    end
  end
end
