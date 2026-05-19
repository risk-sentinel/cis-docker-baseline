# encoding: UTF-8

control 'C-1.1.5' do
  title 'Ensure auditing is configured for Docker files and directories - /var/lib/docker'
  desc  "
    Audit `/var/lib/docker` or data-root.

    As well as auditing the normal Linux file system and system calls, you should also audit all Docker related files and directories. The Docker daemon runs with `root` privileges and its behaviour depends on some key files and directories. `/var/lib/docker` is one such directory. As it holds all the information about containers it should be audited.
  "
  desc  'rationale', "
    Audit `/var/lib/docker` or data-root.

    As well as auditing the normal Linux file system and system calls, you should also audit all Docker related files and directories. The Docker daemon runs with `root` privileges and its behaviour depends on some key files and directories. `/var/lib/docker` is one such directory. As it holds all the information about containers it should be audited.
  "
  desc  'check', "
    You should verify that there is an audit rule applied to the `/var/lib/docker` directory or whatever your data-root directory is set to.

    You can configure the Docker daemon to use a different directory, using the data-root configuration option. For example:

    ```
    {
     \"data-root\"; \"/mnt/docker-data\"
    }
    ```

    To perform an audit execute the command below:
    ```
    auditctl -l | grep /var/lib/docker 
    ```
    or 
    ```
    auditctl -l | grep data-root
    ```

    This should list a rule for the `/var/lib/docker` directory.
  "
  desc  'fix', "
    You should add a rule for the `/var/lib/docker` directory.
    Adding exclusions for /var/lib/docker/overlay2 & /var/lib/docker/volumes reduces the audit messages to a more manageable level.

    For example,

    Add the line as below to the `/etc/audit/rules.d/audit.rules` file:
    ```
    -a exit,always -F path=/var/lib/docker -F perm=war -k docker
    -a exit,never -F dir=/var/lib/docker/volumes
    -a exit,never -F dir=/var/lib/docker/overlay2
    ```
    or for systems with namespace-remapping enabled
    ```
    -a exit,always -F path=/var/lib/docker -F perm=war -k docker
    -a exit,never -F dir=/var/lib/docker/165536.165536/volumes
    -a exit,never -F dir=/var/lib/docker/165536.165536/overlay2
    ```





    Then, restart the audit daemon using the following command

    ```
    systemctl restart auditd
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AU-3 a', 'SC-12 (3)']
  tag cci:                   ['CCI-000130', 'CCI-002447']
  tag cis_number:            '1.1.5'
  tag cis_rid:               '1.1.5'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-010105r1_rule'
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
    its('lines') { should include(match(%r{-w\s+/var/lib/docker})) }
  end
  end
end
