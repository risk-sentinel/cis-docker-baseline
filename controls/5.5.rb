# encoding: UTF-8

control 'C-5.5' do
  title 'Ensure that privileged containers are not used'
  desc  "
    Using the `--privileged` flag provides all Linux kernel capabilities to the container to which it is applied and therefore overwrites the `--cap-add` and `--cap-drop` flags. For this reason you should ensure that it is not used.

    The `--privileged` flag provides all capabilities to the container to which it is applied, and also lifts all the limitations enforced by the device cgroup controller. As a consequence this the container has most of the rights of the underlying host. This flag only exists to allow for specific use cases (for example running Docker within Docker) and should not generally be used.
  "
  desc  'rationale', "
    Using the `--privileged` flag provides all Linux kernel capabilities to the container to which it is applied and therefore overwrites the `--cap-add` and `--cap-drop` flags. For this reason you should ensure that it is not used.

    The `--privileged` flag provides all capabilities to the container to which it is applied, and also lifts all the limitations enforced by the device cgroup controller. As a consequence this the container has most of the rights of the underlying host. This flag only exists to allow for specific use cases (for example running Docker within Docker) and should not generally be used.
  "
  desc  'check', "
    You should run the command below:
    ```
    docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Privileged={{ .HostConfig.Privileged }}'
    ```
    The above command should return `Privileged=false` for each container instance.
  "
  desc  'fix', "
    You should not run containers with the `--privileged` flag.

    For example, do not start a container using the command below:
    ```
    docker run --interactive --tty --privileged centos /bin/bash
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 c']
  tag nist_r4:               ['AC-2 c']
  tag cci:                   ['CCI-002113']
  tag cis_number:            '5.5'
  tag cis_rid:               '5.5'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0505r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  # CapEff with all bits set (or matching the privileged-mode bound) is
  # the runtime fingerprint of `--privileged`.
  cap_eff = file('/proc/self/status').content.to_s[/^CapEff:\s+([0-9a-f]+)/, 1]
  cap_int = cap_eff.to_i(16)
  privileged_threshold = 0x0000003fffffffff
  describe "container CapEff (#{cap_eff}) — privileged-mode runtime fingerprint" do
    subject { cap_int }
    it { should be < privileged_threshold }
  end
end
