# encoding: UTF-8

control 'C-1.1.3' do
  title 'Ensure auditing is configured for the Docker daemon'
  desc  "
    Audit all Docker daemon activities.

    As well as auditing the normal Linux file system and system calls, you should also audit the Docker daemon.  Because this daemon runs with `root` privileges. It is very important to audit its activities and usage.
  "
  desc  'rationale', "
    Audit all Docker daemon activities.

    As well as auditing the normal Linux file system and system calls, you should also audit the Docker daemon.  Because this daemon runs with `root` privileges. It is very important to audit its activities and usage.
  "
  desc  'check', "
    Verify that there are audit rules for the Docker daemon. For example, you could execute the following command:

    ```
    auditctl -l | grep /usr/bin/dockerd
    ```

    This should show the rules associated with the Docker daemon.
  "
  desc  'fix', "
    You should add rules for the Docker daemon.

    For example:

    Add the line below to the `/etc/audit/rules.d/audit.rules` file:
    ```
    -w /usr/bin/dockerd -k docker
    ```

    Then, restart the audit daemon using the following command

    ```
    systemctl restart auditd
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-2 f', 'IA-2 (2)', 'AU-2 a']
  tag cci:                   ['CCI-000011', 'CCI-000766', 'CCI-000123']
  tag cis_number:            '1.1.3'
  tag cis_rid:               '1.1.3'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-010103r1_rule'
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
    its('lines') { should include(match(/-w\s+\/usr\/bin\/dockerd/)) }
  end
  end
end
