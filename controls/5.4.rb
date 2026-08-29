# encoding: UTF-8

control 'C-5.4' do
  title 'Ensure that Linux kernel capabilities are restricted within containers'
  desc  "
    By default, Docker starts containers with a restricted set of Linux kernel capabilities. This means that any process can be granted the required capabilities instead of giving it root access. Using Linux kernel capabilities, processes in general do not need to run as the root user.

    Docker supports the addition and removal of capabilities.  You should remove all capabilities not required for the correct function of the container.

    Specifically, in the default capability set provided by Docker, the `NET_RAW` capability should be removed if not explicitly required, as it can give an attacker with access to a container the ability to create spoofed network traffic.
  "
  desc  'rationale', "
    By default, Docker starts containers with a restricted set of Linux kernel capabilities. This means that any process can be granted the required capabilities instead of giving it root access. Using Linux kernel capabilities, processes in general do not need to run as the root user.

    Docker supports the addition and removal of capabilities.  You should remove all capabilities not required for the correct function of the container.

    Specifically, in the default capability set provided by Docker, the `NET_RAW` capability should be removed if not explicitly required, as it can give an attacker with access to a container the ability to create spoofed network traffic.
  "
  desc  'check', "
    You should run the following command:

    ```
    docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: CapAdd={{ .HostConfig.CapAdd }} CapDrop={{ .HostConfig.CapDrop }}'
    ```
    Verify that the added and deleted Linux kernel capabilities are in line with the ones needed by the container process in each container instance. Specifically, ensure that the `NET_RAW` capability is removed if not required.
  "
  desc  'fix', "
    You should execute the command below to add required capabilities:

    ```
    docker run --cap-add={\"Capability 1\",\"Capability 2\"} ```

    You should execute the command below to remove unneeded capabilities:
    ```
    docker run --cap-drop={\"Capability 1\",\"Capability 2\"} ```

    Alternatively, you could remove all the currently configured capabilities and then restore only the ones you specifically use:
    ```
    docker run --cap-drop=all --cap-add={\"Capability 1\",\"Capability 2\"} ```

    Note that some settings also can be configured using the `--sysctl` option, reducing the need for container capabilities even further. This includes unprivileged ICMP echo sockets without `NET_RAW` and allow opening any port less than 1024 without `NET_BIND_SERVICE`.

    Adding and removing capabilities are also possible when the `docker service` command is used:
    ```
    docker service create --cap-drop=all --cap-add={\"Capability 1\",\"Capability 2\"} ```
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['IA-5 (1) (e)', 'CM-6 a']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-IAM-APM', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 a', 'IA-5 (1) (e)']
  tag cci:                   ['CCI-000200', 'CCI-000363']
  tag cis_number:            '5.4'
  tag cis_rid:               '5.4'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0504r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  # CapBnd / CapEff in /proc/self/status. Default Docker bounding set
  # is roughly 0x00000000a80425fb (14 caps). A capability set equal
  # to 0x000001ffffffffff or with sys_admin (bit 21) usually indicates
  # privileged/unrestricted — fail.
  cap_bnd = file('/proc/self/status').content.to_s[/^CapBnd:\s+([0-9a-f]+)/, 1]
  cap_int = cap_bnd.to_i(16)
  privileged_threshold = 0x0000003fffffffff
  describe "container CapBnd (#{cap_bnd}) — must be restricted (below privileged-mode threshold)" do
    subject { cap_int }
    it { should_not be_nil }
    it { should be < privileged_threshold }
  end
end
