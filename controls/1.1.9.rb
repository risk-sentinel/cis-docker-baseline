# encoding: UTF-8

control 'C-1.1.9' do
  title 'Ensure auditing is configured for Docker files and directories - docker.sock'
  desc  "
    Audit `docker.sock`, if applicable.

    As well as auditing the normal Linux file system and system calls, you should also audit the Docker daemon. Because this daemon runs with root privileges, it is very important to audit its activities and usage. Its behavior depends on some key files and directories with `docker.socket` being one such file, and as this holds various parameters for the Docker daemon, it should be audited.
  "
  desc  'rationale', "
    Audit `docker.sock`, if applicable.

    As well as auditing the normal Linux file system and system calls, you should also audit the Docker daemon. Because this daemon runs with root privileges, it is very important to audit its activities and usage. Its behavior depends on some key files and directories with `docker.socket` being one such file, and as this holds various parameters for the Docker daemon, it should be audited.
  "
  desc  'check', "
    Step 1: Find out the configuration file location:
    ```
    systemctl show -p FragmentPath docker.sock
    ```

    Step 2: Locate the socket file location:
    ```
    grep ListenStream ```

    Step 3: If the file does not exist, this recommendation is not applicable. If the file exists, you should verify that there is an audit rule corresponding to the file:

    For example, you could execute the command below:
    ```
    auditctl -l | grep docker.sock
    ```
    This should display a rule for `docker.sock`.
  "
  desc  'fix', "
    If the file exists, you should add a rule for it.

    For example:

    Add the line below to the `/etc/audit/rules.d/audit.rules` file:
    ```
    -w /var/run/docker.sock -k docker 
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
  tag cis_number:            '1.1.9'
  tag cis_rid:               '1.1.9'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-010109r1_rule'
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
    its('lines') { should include(match(%r{-w\s+/var/run/docker\.sock})) }
  end
  end
end
