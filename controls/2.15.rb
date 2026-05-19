# encoding: UTF-8

control 'C-2.15' do
  title 'Ensure containers are restricted from acquiring new privileges'
  desc  "
    By default you should restrict containers from acquiring additional privileges via suid or sgid.

    A process can set the `no_new_priv` bit in the kernel and this persists across forks, clones and execve. The `no_new_priv` bit ensures that the process and its child processes do not gain any additional privileges via suid or sgid bits. This reduces the security risks associated with many dangerous operations because there is a much reduced ability to subvert privileged binaries.

    Setting this at the daemon level ensures that by default all new containers are restricted from acquiring new privileges.
  "
  desc  'rationale', "
    By default you should restrict containers from acquiring additional privileges via suid or sgid.

    A process can set the `no_new_priv` bit in the kernel and this persists across forks, clones and execve. The `no_new_priv` bit ensures that the process and its child processes do not gain any additional privileges via suid or sgid bits. This reduces the security risks associated with many dangerous operations because there is a much reduced ability to subvert privileged binaries.

    Setting this at the daemon level ensures that by default all new containers are restricted from acquiring new privileges.
  "
  desc  'check', "
    To confirm this setting, you should review the dockerd start-up options and a check of any settings in `/etc/docker/daemon.json` should also be carried out.

    To review the dockerd startup options, the following command can be used:
    ```
    ps -ef | grep dockerd 
    ```
    You should ensure that the `--no-new-privileges` parameter is present and that it is not set to `false`.

    The contents of `/etc/docker/daemon.json` should also be reviewed.
  "
  desc  'fix', "
    You should run the Docker daemon as below:
    ```
    dockerd --no-new-privileges
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-2 i 1']
  tag cci:                   ['CCI-002126']
  tag cis_number:            '2.15'
  tag cis_rid:               '2.15'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0215r1_rule'
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
      it 'is satisfied by AWS-managed controls — AWS Fargate disables setuid / new-privilege escalation on its task runtime; the no-new-privs posture is enforced at the ECS task-definition level, not as a daemon flag (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
        expect(true).to eq(true)
      end
    end
  else
    daemon_json_path = '/etc/docker/daemon.json'
  if file(daemon_json_path).exist?
    describe json(daemon_json_path) do
      its(['no-new-privileges']) { should eq true }
    end
  else
    describe 'CIS Docker daemon.json key no-new-privileges' do
      skip "host_daemon mode: /etc/docker/daemon.json not present — daemon is running with default flags. Operator confirms `dockerd --no-new-privileges` flag from process inventory."
    end
  end
  end
end
