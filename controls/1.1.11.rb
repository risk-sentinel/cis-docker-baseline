# encoding: UTF-8

control 'C-1.1.11' do
  title 'Ensure auditing is configured for Docker files and directories - /etc/docker/daemon.json'
  desc  "
    Audit `/etc/docker/daemon.json`, if applicable.

    As well as auditing the normal Linux file system and system calls, you should also audit all Docker related files and directories. The Docker daemon runs with `root` privileges and its behavior depends on some key files and directories. `/etc/docker/daemon.json` is one such file. This holds various parameters for the Docker daemon, and as such it should be audited.
  "
  desc  'rationale', "
    Audit `/etc/docker/daemon.json`, if applicable.

    As well as auditing the normal Linux file system and system calls, you should also audit all Docker related files and directories. The Docker daemon runs with `root` privileges and its behavior depends on some key files and directories. `/etc/docker/daemon.json` is one such file. This holds various parameters for the Docker daemon, and as such it should be audited.
  "
  desc  'check', "
    You should verify that there is an audit rule associated with the `/etc/docker/daemon.json` file.

    For example, you could execute the command below:
    ```
    auditctl -l | grep /etc/docker/daemon.json
    ```
    This should display a rule for the `/etc/docker/daemon.json` file.
  "
  desc  'fix', "
    You should add a rule for the `/etc/docker/daemon.json` file.

    For example:

    Add the line below to the `/etc/audit/audit.rules` file:
    ```
    -w /etc/docker/daemon.json -k docker 
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
  tag cis_number:            '1.1.11'
  tag cis_rid:               '1.1.11'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-010111r1_rule'
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
    its('lines') { should include(match(%r{-w\s+/etc/docker/daemon\.json})) }
  end
  end
end
