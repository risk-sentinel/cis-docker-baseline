# encoding: UTF-8

control 'C-5.26' do
  title 'Ensure that  the container is restricted from acquiring additional privileges'
  desc  "
    You should restrict the container from acquiring additional privileges via suid or sgid bits.

    A process can set the `no_new_priv` bit in the kernel and this persists across forks, clones and execve. The `no_new_priv` bit ensures that the process and its child processes do not gain any additional privileges via suid or sgid bits. This reduces the danger associated with many operations because the possibility of subverting privileged binaries is lessened.
  "
  desc  'rationale', "
    You should restrict the container from acquiring additional privileges via suid or sgid bits.

    A process can set the `no_new_priv` bit in the kernel and this persists across forks, clones and execve. The `no_new_priv` bit ensures that the process and its child processes do not gain any additional privileges via suid or sgid bits. This reduces the danger associated with many operations because the possibility of subverting privileged binaries is lessened.
  "
  desc  'check', "
    You should run the following command:

    ```
    docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: SecurityOpt={{ .HostConfig.SecurityOpt }}'
    ```

    This command should return all the security options currently configured for containers. `no-new-privileges` should be one of them.

    Note that the SecurityOpt response will be empty (i.e. `SecurityOpt= `) even if `\"no-new-privileges\": true` has been configured in the Docker daemon.json configuration file.
  "
  desc  'fix', "
    You should start your container with the options below:

    ```
    docker run --rm -it --security-opt=no-new-privileges ubuntu bash
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-2 c']
  tag cci:                   ['CCI-002113']
  tag cis_number:            '5.26'
  tag cis_rid:               '5.26'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0526r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  # /proc/self/status NoNewPrivs: 0 or 1. CIS wants 1.
  no_new_privs = file('/proc/self/status').content.to_s[/^NoNewPrivs:\s+(\d+)/, 1]
  describe "container NoNewPrivs (#{no_new_privs.inspect}) — must be 1" do
    subject { no_new_privs }
    it { should eq '1' }
  end
end
