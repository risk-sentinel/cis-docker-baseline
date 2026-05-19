# encoding: UTF-8

control 'C-5.19' do
  title 'Ensure that the default ulimit is overwritten at runtime if needed'
  desc  "
    The default ulimit is set at the Docker daemon level. However, if you need to, you may override the default ulimit setting during container runtime.

    `ulimit` provides control over the resources available to the shell and to processes started by it. Setting system resource limits in a prudent fashion, protects against denial of service conditions. On occasion, legitimate users and processes can accidentally overuse system resources and cause systems be degraded or even unresponsive.

    The default ulimit set at the Docker daemon level should be honored. If the default ulimit settings are not appropriate for a particular container instance, you may override them as an exception, but this should not be done routinely.  If many of your container instances are exceeding your ulimit settings, you should consider changing the default settings to something that is more appropriate for your needs.
  "
  desc  'rationale', "
    The default ulimit is set at the Docker daemon level. However, if you need to, you may override the default ulimit setting during container runtime.

    `ulimit` provides control over the resources available to the shell and to processes started by it. Setting system resource limits in a prudent fashion, protects against denial of service conditions. On occasion, legitimate users and processes can accidentally overuse system resources and cause systems be degraded or even unresponsive.

    The default ulimit set at the Docker daemon level should be honored. If the default ulimit settings are not appropriate for a particular container instance, you may override them as an exception, but this should not be done routinely.  If many of your container instances are exceeding your ulimit settings, you should consider changing the default settings to something that is more appropriate for your needs.
  "
  desc  'check', "
    You should run the command below:
    ```
    docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Ulimits={{ .HostConfig.Ulimits }}'
    ```
    This command should return `Ulimits= ` for each container instance unless there is a need in a specific case to override the default settings.
  "
  desc  'fix', "
    You should only override the default ulimit settings if needed in a specific case.

    For example, to override default ulimit settings start a container as below:

    ```
    docker run -ti -d --ulimit nofile=1024:1024 centos sleep 1000
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['IA-5 (1) (e)']
  tag cci:                   ['CCI-000200']
  tag cis_number:            '5.19'
  tag cis_rid:               '5.19'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0519r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag exec_validated:        false

  describe 'Requires manual review and attestation' do
    skip "Requires manual review and attestation provided for this control (\"appropriate\" ulimit overrides depend on the consumer's workload mix; operators attest from the task-definition ulimits field)"
  end
end
