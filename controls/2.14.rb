# encoding: UTF-8

control 'C-2.14' do
  title 'Ensure centralized and remote logging is configured'
  desc  "
    Docker supports various logging mechanisms. A preferable method for storing logs is one that supports centralized and remote management.

    Centralized and remote logging ensures that all important log records are safe even in the event of a major data availability issue . Docker supports various logging methods and you should use the one that best corresponds to your IT security policy.
  "
  desc  'rationale', "
    Docker supports various logging mechanisms. A preferable method for storing logs is one that supports centralized and remote management.

    Centralized and remote logging ensures that all important log records are safe even in the event of a major data availability issue . Docker supports various logging methods and you should use the one that best corresponds to your IT security policy.
  "
  desc  'check', "
    Run `docker info` and ensure that the `Logging Driver `property set as appropriate.
    ```
    docker info --format '{{ .LoggingDriver }}' 
    ```
    Alternatively, the below command would give you the `--log-driver` setting. If configured you should ensure that it is set appropriately.

    ```
    grep \"--log-driver\" /etc/docker/daemon.json
    ```
    The contents of `/etc/docker/daemon.json` should also be reviewed for this setting.
  "
  desc  'fix', "
    Step 1: Set up the desired log driver following its documentation.

    Step 2: Start the docker daemon using that logging driver.

    For example:
    ```
    dockerd --log-driver=syslog --log-opt syslog-address=tcp://192.xxx.xxx.xxx
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-2 (2)', 'AC-2 c', 'AU-1 a 1 (a)', 'AU-5 b']
  tag cci:                   ['CCI-001682', 'CCI-002113', 'CCI-000117', 'CCI-000140']
  tag cis_number:            '2.14'
  tag cis_rid:               '2.14'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0214r1_rule'
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
      it 'is satisfied by AWS-managed controls — AWS-side logging happens at the ECS task-definition log-driver level (configured via awslogs / firelens / etc.), not at the daemon level on Fargate (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
        expect(true).to eq(true)
      end
    end
  else
    daemon_json_path = '/etc/docker/daemon.json'
  acceptable_drivers = %w[awslogs splunk fluentd gelf syslog journald]
  if file(daemon_json_path).exist?
    describe json(daemon_json_path) do
      its(['log-driver']) { should be_in acceptable_drivers }
    end
  else
    describe 'host_daemon centralised logging — daemon.json log-driver' do
      skip 'host_daemon mode: /etc/docker/daemon.json missing — defaults to local json-file. Configure a remote log driver to satisfy CIS 2.14.'
    end
  end
  end
end
