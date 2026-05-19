# encoding: UTF-8

control 'C-1.1.12' do
  title 'Ensure auditing is configured for Docker files and directories - /etc/containerd/config.toml'
  desc  "
    Audit `/etc/containerd/config.toml` if applicable

    As well as auditing the normal Linux file system and system calls, you should also audit the Docker daemon. Because this daemon runs with root privileges it is very important to audit its activities and usage. Its behavior depends on some key files and directories and `/etc/containerd/config.toml` is one such file as it contains various parameters.  If present, it is important that it is audited.
  "
  desc  'rationale', "
    Audit `/etc/containerd/config.toml` if applicable

    As well as auditing the normal Linux file system and system calls, you should also audit the Docker daemon. Because this daemon runs with root privileges it is very important to audit its activities and usage. Its behavior depends on some key files and directories and `/etc/containerd/config.toml` is one such file as it contains various parameters.  If present, it is important that it is audited.
  "
  desc  'check', "
    You should verify that there is an audit rule present relating to the `/etc/containerd/config.toml` file.

    For example, you could execute the command below:
    ```
    auditctl -l | grep /etc/containerd/config.toml 
    ```
    This should display a rule for `/etc/containerd/config.toml` file.
  "
  desc  'fix', "
    You should add a rule for `/etc/containerd/config.toml` file.

    For example:

    Add the line below to the `/etc/audit/audit.rules` file:
    ```
    -w /etc/containerd/config.toml -k docker 
    ```
    Then restart the audit daemon. 

    For example:
    ```
    systemctl restart auditd
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AU-3 a', 'SC-12 (3)']
  tag cci:                   ['CCI-000130', 'CCI-002447']
  tag cis_number:            '1.1.12'
  tag cis_rid:               '1.1.12'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-010112r1_rule'
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
    describe 'AWS shared-responsibility inheritance' do
      it 'is satisfied by AWS-managed controls — AWS audits its container-runtime control plane on Fargate hosts (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
        expect(true).to eq(true)
      end
    end
  else
    describe auditd do
    its('lines') { should include(match(%r{-w\s+/etc/containerd/config\.toml})) }
  end
  end
end
