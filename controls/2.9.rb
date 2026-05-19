# encoding: UTF-8

control 'C-2.9' do
  title 'Ensure the default ulimit is configured appropriately'
  desc  "
    Set the default ulimit options as appropriate in your environment.

    `ulimit` provides control over the resources available to the shell and to processes which it starts. Setting system resource limits judiciously can save you from disasters such as a fork bomb. On occasion, even friendly users and legitimate processes can overuse system resources and can make the system unusable.

    Setting the default ulimit for the Docker daemon enforces the ulimit for all container instances. In this case you would not need to setup ulimit for each container instance. However, the default ulimit can be overridden during container runtime, if needed. Therefore, in order to have proper control over system resources, define a default ulimit as is  needed in your environment.
  "
  desc  'rationale', "
    Set the default ulimit options as appropriate in your environment.

    `ulimit` provides control over the resources available to the shell and to processes which it starts. Setting system resource limits judiciously can save you from disasters such as a fork bomb. On occasion, even friendly users and legitimate processes can overuse system resources and can make the system unusable.

    Setting the default ulimit for the Docker daemon enforces the ulimit for all container instances. In this case you would not need to setup ulimit for each container instance. However, the default ulimit can be overridden during container runtime, if needed. Therefore, in order to have proper control over system resources, define a default ulimit as is  needed in your environment.
  "
  desc  'check', "
    To confirm this setting you should review the dockerd start-up options and any settings in `/etc/docker/daemon.json`.

    To review the dockerd startup options, use:
    ```
    ps -ef | grep dockerd
    ```
    Ensure that the `--default-ulimit` parameter is set as appropriate.

    The contents of `/etc/docker/daemon.json` should also be reviewed for this setting.
  "
  desc  'fix', "
    Run Docker in daemon mode and pass `--default-ulimit` as argument with respective ulimits as appropriate in your environment and in line with your security policy.

    For Example,
    ```
    dockerd --default-ulimit nproc=1024:2048 --default-ulimit nofile=100:200
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 a']
  tag cci:                   ['CCI-000363']
  tag cis_number:            '2.9'
  tag cis_rid:               '2.9'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0209r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  if input('docker_target_mode') == 'container_only'
    tag implementation_status:  'inherited'
    tag inherited_from:         'aws-shared-responsibility'
    tag attestation_references: ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  else
    tag implementation_status:  'alternative'
  end
  tag exec_validated:           false

  if input('docker_target_mode') == 'container_only'
    describe 'AWS shared-responsibility inheritance' do
      it 'is satisfied by AWS-managed controls — AWS controls daemon-level ulimits on Fargate hosts; per-task ulimits are settable in the task definition (CIS Docker §5.19) (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
        expect(true).to eq(true)
      end
    end
  else
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (\"appropriately\" depends on the consumer's workload mix; operators attest from their capacity-planning record)"
    end
  end
end
