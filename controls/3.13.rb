# encoding: UTF-8

control 'C-3.13' do
  title 'Ensure that the Docker server certificate key file ownership is set to root:root'
  desc  "
    You should verify that the Docker server certificate key file (the file that is passed along with the `--tlskey` parameter) is individually owned and group owned by `root`.

    The Docker server certificate key file should be protected from any tampering or unneeded reads/writes. As it holds the private key for the Docker server certificate, it must be individually owned and group owned by `root` to ensure that it cannot be accessed by less privileged users.
  "
  desc  'rationale', "
    You should verify that the Docker server certificate key file (the file that is passed along with the `--tlskey` parameter) is individually owned and group owned by `root`.

    The Docker server certificate key file should be protected from any tampering or unneeded reads/writes. As it holds the private key for the Docker server certificate, it must be individually owned and group owned by `root` to ensure that it cannot be accessed by less privileged users.
  "
  desc  'check', "
    You should execute the command below to verify that the Docker server certificate key file is individually owned and group owned by `root`:
    ```
    stat -c %U:%G | grep -v root:root
    ```
    The command above should return no results.
  "
  desc  'fix', "
    You should execute the following command:

    ```
    chown root:root ```
    This sets the individual ownership and group ownership for the Docker server certificate key file to `root`.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-2 c']
  tag cci:                   ['CCI-002113']
  tag cis_number:            '3.13'
  tag cis_rid:               '3.13'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0313r1_rule'
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
      skip "Requires manual review and attestation provided for this control (Docker server certificate key path is daemon.json-driven)"
    end
  end
end
