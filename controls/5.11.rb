# encoding: UTF-8

control 'C-5.11' do
  title 'Ensure that the memory usage for containers is limited'
  desc  "
    By default, all containers on a Docker host share resources equally. By using the resource management capabilities of the Docker host, you can control the amount of memory that a container is able to use.

    By default a container can use all of the memory on the host. You can use memory limit mechanisms to prevent a denial of service occurring where one container consumes all of the host's resources and other containers on the same host are therefore not able to function. Having no limit on memory usage can lead to issues where one container can easily make the whole system unstable and as a result unusable.
  "
  desc  'rationale', "
    By default, all containers on a Docker host share resources equally. By using the resource management capabilities of the Docker host, you can control the amount of memory that a container is able to use.

    By default a container can use all of the memory on the host. You can use memory limit mechanisms to prevent a denial of service occurring where one container consumes all of the host's resources and other containers on the same host are therefore not able to function. Having no limit on memory usage can lead to issues where one container can easily make the whole system unstable and as a result unusable.
  "
  desc  'check', "
    You should run the command below:
    ```
    docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Memory={{ .HostConfig.Memory }}'
    ```
    If this command returns `0`, it means that memory limits are not in place; if it returns a non-zero value, it means that they are in place.
  "
  desc  'fix', "
    You should run the container with only as much memory as it requires by using the `--memory` argument. 

    For example, you could run a container using the command below:
    ```
    docker run -d --memory 256m centos sleep 1000
    ```
    In the example above, the container is started with a memory limit of 256 MB.

    Verify the memory settings by using the command below:
    ```
    docker inspect --format='{{ .Id }}: Memory={{.HostConfig.Memory}} KernelMemory={{.HostConfig.KernelMemory}} Swap={{.HostConfig.MemorySwap}}' ```
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '5.11'
  tag cis_rid:               '5.11'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0511r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  candidates = ['/sys/fs/cgroup/memory.max', '/sys/fs/cgroup/memory/memory.limit_in_bytes']
  cgroup_file = candidates.find { |p| file(p).exist? }
  if cgroup_file.nil?
    describe 'container memory cgroup limit' do
      skip 'pending-resource: no readable cgroup memory limit file at the standard cgroup-v2 or cgroup-v1 paths.'
    end
  else
    value = file(cgroup_file).content.to_s.strip
    describe "container memory limit (#{cgroup_file} = #{value.inspect})" do
      subject { value }
      it { should_not eq 'max' }
      it { should_not match(/^9223372036854775807$/) }
    end
  end
end
