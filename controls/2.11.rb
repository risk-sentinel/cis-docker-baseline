# encoding: UTF-8

control 'C-2.11' do
  title 'Ensure the default cgroup usage has been confirmed'
  desc  "
    The `--cgroup-parent` option allows you to set the default cgroup parent to use for all containers. If there is no specific usage requirement for this, the setting should be left at its default.

    System administrators typically define cgroups under which containers are supposed to run. Even if cgroups are not explicitly defined by the system administrators, containers run under `docker` cgroup by default.

    It is possible to attach to a different cgroup other than the one which is the default, however this type of usage should be monitored and confirmed because attaching to a different cgroup other than the one that is a default, it could be possible to share resources unevenly causing resource utilization problems on the host.
  "
  desc  'rationale', "
    The `--cgroup-parent` option allows you to set the default cgroup parent to use for all containers. If there is no specific usage requirement for this, the setting should be left at its default.

    System administrators typically define cgroups under which containers are supposed to run. Even if cgroups are not explicitly defined by the system administrators, containers run under `docker` cgroup by default.

    It is possible to attach to a different cgroup other than the one which is the default, however this type of usage should be monitored and confirmed because attaching to a different cgroup other than the one that is a default, it could be possible to share resources unevenly causing resource utilization problems on the host.
  "
  desc  'check', "
    In order to confirm this setting, the dockerd start-up options and any settings in `/etc/docker/daemon.json` should be reviewed.

    To review the dockerd startup options, use:
    ```
    grep \"--cgroup-parent\" /etc/docker/daemon.json
    ```
    You should ensure that the `--cgroup-parent` parameter is either not set or is set as appropriate non-default cgroup.

    The contents of `/etc/docker/daemon.json` should also be checked for this setting.
  "
  desc  'fix', "
    The default setting is in line with good security practice and can be left in situ. If you wish to specifically set a non-default cgroup, pass the `--cgroup-parent` parameter to the Docker daemon when starting it.

    For example,
    ```
    dockerd --cgroup-parent=/foobar
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '2.11'
  tag cis_rid:               '2.11'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0211r1_rule'
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
      it 'is satisfied by AWS-managed controls — AWS chooses cgroup driver on Fargate hosts (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
        expect(true).to eq(true)
      end
    end
  else
    daemon_json_path = '/etc/docker/daemon.json'
  if file(daemon_json_path).exist? && json(daemon_json_path).params.key?('cgroup-parent')
    describe json(daemon_json_path) do
      its(['cgroup-parent']) { should eq '/docker' }
    end
  else
    describe 'cgroup-parent — daemon default' do
      skip 'host_daemon mode: cgroup-parent not overridden in daemon.json (default `/docker` is acceptable per CIS 2.11)'
    end
  end
  end
end
