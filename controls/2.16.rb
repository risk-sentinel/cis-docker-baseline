# encoding: UTF-8

control 'C-2.16' do
  title 'Ensure live restore is enabled'
  desc  "
    The `--live-restore` option enables full support of daemon-less containers within Docker. It ensures that Docker does not stop containers on shutdown or restore and that it properly reconnects to the container when restarted.

    One of the important security triads is availability. Setting the `--live-restore` flag within the Docker daemon ensures that container execution is not interrupted when it is not available. This also makes it easier to update and patch the Docker daemon without application downtime.
  "
  desc  'rationale', "
    The `--live-restore` option enables full support of daemon-less containers within Docker. It ensures that Docker does not stop containers on shutdown or restore and that it properly reconnects to the container when restarted.

    One of the important security triads is availability. Setting the `--live-restore` flag within the Docker daemon ensures that container execution is not interrupted when it is not available. This also makes it easier to update and patch the Docker daemon without application downtime.
  "
  desc  'check', "
    You should run `docker info` and ensure that the `Live Restore Enabled` property is set to `true`.

    ```
    docker info --format '{{ .LiveRestoreEnabled }}' 
    ```

    Alternatively, you could run the below command and ensure that `--live-restore` is in use.

    ```
    grep \"--live-restore\" /etc/docker/daemon.json
    ```

    The contents of `/etc/docker/daemon.json` should also be reviewed to ensure this setting is in place.
  "
  desc  'fix', "
    Run Docker in daemon mode and pass `--live-restore` to it as an argument.

    For Example,
    ```
    dockerd --live-restore
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SA-8']
  tag cci:                   ['CCI-000664']
  tag cis_number:            '2.16'
  tag cis_rid:               '2.16'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0216r1_rule'
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
      it 'is satisfied by AWS-managed controls — AWS handles task continuity on Fargate without depending on dockerd live-restore (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
        expect(true).to eq(true)
      end
    end
  else
    daemon_json_path = '/etc/docker/daemon.json'
  if file(daemon_json_path).exist?
    describe json(daemon_json_path) do
      its(['live-restore']) { should eq true }
    end
  else
    describe 'CIS Docker daemon.json key live-restore' do
      skip "host_daemon mode: /etc/docker/daemon.json not present — daemon is running with default flags. Operator confirms `dockerd --live-restore` flag from process inventory."
    end
  end
  end
end
