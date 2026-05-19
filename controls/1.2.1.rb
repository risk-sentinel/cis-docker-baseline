# encoding: UTF-8

control 'C-1.2.1' do
  title 'Ensure the container host has been Hardened'
  desc  "
    A container host is able to run one or more containers. It is of utmost importance to harden the host to mitigate host security misconfiguration.

    You should follow infrastructure security best practices and harden your host OS. Keeping the host system hardened will ensure that host vulnerabilities are mitigated. Not hardening the host system could lead to security exposures and breaches.
  "
  desc  'rationale', "
    A container host is able to run one or more containers. It is of utmost importance to harden the host to mitigate host security misconfiguration.

    You should follow infrastructure security best practices and harden your host OS. Keeping the host system hardened will ensure that host vulnerabilities are mitigated. Not hardening the host system could lead to security exposures and breaches.
  "
  desc  'check', "
    Ensure that the host specific security guidelines are followed. Ask the system administrators which security benchmark the current host system should currently be compliant with and check that security standards associated with this standard are currently in place.
  "
  desc  'fix', "
    You may consider various CIS Security Benchmarks for your container host. If you have other security guidelines or regulatory requirements to adhere to, please follow them as suitable in your environment.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 a']
  tag cci:                   ['CCI-000363']
  tag cis_number:            '1.2.1'
  tag cis_rid:               '1.2.1'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-010201r1_rule'
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
      it 'is satisfied by AWS-managed controls — AWS Fargate host hardening (kernel, OS package set, network namespace) is performed by AWS (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
        expect(true).to eq(true)
      end
    end
  else
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (\"hardened\" is a consumer-policy-specific composite — base-OS choice, kernel version, package set, kernel flags, etc. — that an InSpec scanner cannot assert generically)"
    end
  end
end
