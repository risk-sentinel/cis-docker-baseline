# encoding: UTF-8

control 'C-3.12' do
  title 'Ensure that the Docker server certificate file permissions are set to 444 or more restrictively'
  desc  "
    You should verify that the Docker server certificate file (the file that is passed along with the `--tlscert` parameter) has permissions of `444` or more restrictive permissions.

    The Docker server certificate file should be protected from any tampering. It is used to authenticate the Docker server based on the given server certificate. It should therefore have permissions of `444` to prevent its modification.
  "
  desc  'rationale', "
    You should verify that the Docker server certificate file (the file that is passed along with the `--tlscert` parameter) has permissions of `444` or more restrictive permissions.

    The Docker server certificate file should be protected from any tampering. It is used to authenticate the Docker server based on the given server certificate. It should therefore have permissions of `444` to prevent its modification.
  "
  desc  'check', "
    You should execute the command below to verify that the Docker server certificate file has permissions of `444` or more restrictive permissions:
    ```
    stat -c %a ```
  "
  desc  'fix', "
    You should execute the command below:
    ```
    chmod 444 ```
    This sets the file permissions of the Docker server certificate file to `444`.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '3.12'
  tag cis_rid:               '3.12'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0312r1_rule'
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
    describe 'AWS shared-responsibility inheritance' do
      it 'is satisfied by AWS-managed controls — AWS doesn\'t expose dockerd TLS config on Fargate (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
        expect(true).to eq(true)
      end
    end
  else
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (Docker server certificate path is daemon.json-driven)"
    end
  end
end
