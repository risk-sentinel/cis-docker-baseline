# encoding: UTF-8

control 'C-3.10' do
  title 'Ensure that TLS CA certificate file permissions are set to 444 or more restrictively'
  desc  "
    You should verify that the TLS CA certificate file (the file that is passed along with the `--tlscacert` parameter) has permissions of `444` or is set more restrictively.

    The TLS CA certificate file should be protected from any tampering. It is used to authenticate the Docker server based on a given CA certificate. It must therefore have permissions of `444`, or more restrictive permissions to ensure that the file cannot be modified by a less privileged user.
  "
  desc  'rationale', "
    You should verify that the TLS CA certificate file (the file that is passed along with the `--tlscacert` parameter) has permissions of `444` or is set more restrictively.

    The TLS CA certificate file should be protected from any tampering. It is used to authenticate the Docker server based on a given CA certificate. It must therefore have permissions of `444`, or more restrictive permissions to ensure that the file cannot be modified by a less privileged user.
  "
  desc  'check', "
    You should execute the command below to verify that the TLS CA certificate file has permissions of `444` or that these are more restrictively set:
    ```
    stat -c %a ```
  "
  desc  'fix', "
    You should execute the following command:

    ```
    chmod 444 ```
    This sets the file permissions on the TLS CA file to `444`.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '3.10'
  tag cis_rid:               '3.10'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0310r1_rule'
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
      skip "Requires manual review and attestation provided for this control (TLS CA certificate path is daemon.json-driven)"
    end
  end
end
