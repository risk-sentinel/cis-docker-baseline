# encoding: UTF-8

control 'C-5.25' do
  title 'Ensure that cgroup usage is confirmed'
  desc  "
    It is possible to attach to a particular cgroup when a container is instantiated. Confirming cgroup usage would ensure that containers are running in defined cgroups.

    System administrators typically define cgroups in which containers are supposed to run. If cgroups are not explicitly defined by the system administrator, containers run in the `docker` cgroup by default.

    At run time, it is possible to attach a container to a different cgroup other than the one originally defined. This usage should be monitored and confirmed, as by attaching to a different cgroup, excess permissions and resources might be granted to the container and this can therefore prove to be a security risk.
  "
  desc  'rationale', "
    It is possible to attach to a particular cgroup when a container is instantiated. Confirming cgroup usage would ensure that containers are running in defined cgroups.

    System administrators typically define cgroups in which containers are supposed to run. If cgroups are not explicitly defined by the system administrator, containers run in the `docker` cgroup by default.

    At run time, it is possible to attach a container to a different cgroup other than the one originally defined. This usage should be monitored and confirmed, as by attaching to a different cgroup, excess permissions and resources might be granted to the container and this can therefore prove to be a security risk.
  "
  desc  'check', "
    You should run the following command:
    ```
    docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: CgroupParent={{ .HostConfig.CgroupParent }}' 
    ```
    The above command returns the cgroup where the containers are running. If it is blank, it means that containers are running under the default docker cgroup.  Any other return value indicates that the system is not configured in line with good security practice.
  "
  desc  'fix', "
    You should not use the `--cgroup-parent` option within the `docker run` command unless strictly required.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '5.25'
  tag cis_rid:               '5.25'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0525r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  describe file('/proc/self/cgroup') do
    its('content') { should_not be_empty }
  end
end
