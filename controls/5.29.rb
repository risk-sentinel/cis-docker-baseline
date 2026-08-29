# encoding: UTF-8

control 'C-5.29' do
  title 'Ensure that the PIDs cgroup limit is used'
  desc  "
    You should use the `--pids-limit` flag at container runtime.

    Attackers could launch a fork bomb with a single command inside the container. This fork bomb could crash the entire system and would require a restart of the host to make the system functional again. Using the PIDs cgroup parameter `--pids-limit` would prevent this kind of attack by restricting the number of forks that can happen inside a container within a specified time frame.
  "
  desc  'rationale', "
    You should use the `--pids-limit` flag at container runtime.

    Attackers could launch a fork bomb with a single command inside the container. This fork bomb could crash the entire system and would require a restart of the host to make the system functional again. Using the PIDs cgroup parameter `--pids-limit` would prevent this kind of attack by restricting the number of forks that can happen inside a container within a specified time frame.
  "
  desc  'check', "
    You should run the command below and ensure that `PidsLimit` is not set to 0 or -1. A `PidsLimit` of 0 or -1 means that any number of processes can be forked concurrently inside the container.

    ```
    docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: PidsLimit={{ .HostConfig.PidsLimit }}'
    ```
  "
  desc  'fix', "
    Use `--pids-limit` flag with an appropriate value when launching the container.

    For example:
    ```
    docker run -it --pids-limit 100 ```
    In the above example, the number of processes allowed to run at any given time is set to 100. After a limit of 100 concurrently running processes is reached, Docker would restrict any new process creation.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['IA-5 (1) (e)']
  tag ksi:                   ['KSI-IAM-APM']
  tag nist_r4:               ['IA-5 (1) (e)']
  tag cci:                   ['CCI-000200']
  tag cis_number:            '5.29'
  tag cis_rid:               '5.29'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0529r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  candidates = ['/sys/fs/cgroup/pids.max']
  cgroup_file = candidates.find { |p| file(p).exist? }
  if cgroup_file.nil?
    describe 'container PIDs cgroup limit' do
      skip 'pending-resource: no readable pids.max at /sys/fs/cgroup/pids.max — likely a cgroup-v1 system or restricted /sys mount.'
    end
  else
    value = file(cgroup_file).content.to_s.strip
    describe "container PIDs cgroup limit (#{cgroup_file} = #{value.inspect})" do
      subject { value }
      it { should_not eq 'max' }
    end
  end
end
