# encoding: UTF-8

control 'C-5.22' do
  title 'Ensure the default seccomp profile is not Disabled'
  desc  "
    Seccomp filtering provides a means for a process to specify a filter for incoming system calls. The default Docker seccomp profile works on a whitelist basis and allows for a large number of common system calls, whilst blocking all others.  This filtering should not be disabled unless it causes a problem with your container application usage.

    A large number of system calls are exposed to every userland process with many of them going unused for the entire lifetime of the process. Most of applications do not need all these system calls and would therefore benefit from having a reduced set of available system calls. Having a reduced set of system calls reduces the total kernel surface exposed to the application and thus improvises application security.
  "
  desc  'rationale', "
    Seccomp filtering provides a means for a process to specify a filter for incoming system calls. The default Docker seccomp profile works on a whitelist basis and allows for a large number of common system calls, whilst blocking all others.  This filtering should not be disabled unless it causes a problem with your container application usage.

    A large number of system calls are exposed to every userland process with many of them going unused for the entire lifetime of the process. Most of applications do not need all these system calls and would therefore benefit from having a reduced set of available system calls. Having a reduced set of system calls reduces the total kernel surface exposed to the application and thus improvises application security.
  "
  desc  'check', "
    You should run the following command:
    ```
    docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: SecurityOpt={{ .HostConfig.SecurityOpt }}'   
    ```
    This should return either ` ` or your modified seccomp profile. If it returns `[seccomp:unconfined]`, the container is running without any seccomp profiles and is therefore not configured in line with good security practice.
  "
  desc  'fix', "
    By default, seccomp profiles are enabled. You do not need to do anything unless you want to modify and use a modified seccomp profile.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-7 a', 'AC-4']
  tag cci:                   ['CCI-001097', 'CCI-001414']
  tag cis_number:            '5.22'
  tag cis_rid:               '5.22'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0522r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  # /proc/self/status Seccomp field: 0=disabled, 1=strict, 2=filter.
  # CIS wants !=0 (a profile is applied).
  seccomp = file('/proc/self/status').content.to_s[/^Seccomp:\s+(\d+)/, 1].to_i
  describe "container Seccomp mode (#{seccomp}) — must not be 0 (disabled)" do
    subject { seccomp }
    it { should be > 0 }
  end
end
