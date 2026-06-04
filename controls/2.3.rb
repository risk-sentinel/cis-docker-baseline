# encoding: UTF-8

control 'C-2.3' do
  title 'Ensure the logging level is set to \'info\''
  desc  "
    Set Docker daemon log level to `info`.

    Setting up an appropriate log level, configures the Docker daemon to log events that you would want to review later. A base log level of `info` and above would capture all logs except debug logs. Until and unless required, you should not run Docker daemon at `debug` log level.
  "
  desc  'rationale', "
    Set Docker daemon log level to `info`.

    Setting up an appropriate log level, configures the Docker daemon to log events that you would want to review later. A base log level of `info` and above would capture all logs except debug logs. Until and unless required, you should not run Docker daemon at `debug` log level.
  "
  desc  'check', "
    To confirm this setting a combination of reviewing the dockerd start-up options and a review of any settings in `/etc/docker/daemon.json` should be completed.

    To review the dockerd startup options, use:
    ```
    grep \"log-level\" /etc/docker/daemon.json
    ```
    Ensure that either the `--log-level` parameter is not present or if present, then it is set to `info`.  

    The contents of `/etc/docker/daemon.json` should also be reviewed for this setting.
  "
  desc  'fix', "
    Ensure that the Docker daemon configuration file has the following configuration included

    ```
    \"log-level\": \"info\"
    ```

    Alternatively, run the Docker daemon as below:
    ```
    dockerd --log-level=\"info\"
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-2 f', 'IA-2 (2)', 'AU-3 a']
  tag cci:                   ['CCI-000011', 'CCI-000766', 'CCI-000130']
  tag cis_number:            '2.3'
  tag cis_rid:               '2.3'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0203r1_rule'
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
    uri = input('inherited_evidence_uri', value: '')
    uri = attestation_uri(:leveraged, 'aws-soc2-type2', ext: 'json') if uri.to_s.empty?
    if uri.to_s.empty?
      describe 'AWS shared-responsibility evidence (no leveraged source configured)' do
        skip 'inherited-from-aws: set leveraged_evidence_base / inherited_evidence_uri to the pulled AWS evidence manifest (SOC 2 / FedRAMP / ISO), or `saf attest apply`.'
      end
    else
      doc = document_attestation(uri, max_age_days: input('leveraged_evidence_max_age_days', value: 365))
      describe "AWS shared-responsibility leveraged evidence (#{uri})" do
        it('reachable') { expect(doc.connection_error).to be_nil, "evidence unreachable: #{doc.connection_error}" }
        it('exists') { expect(doc.exists?).to eq(true) }
        it("current") { expect(doc.current?).to eq(true) }
      end
    end
  else
    daemon_json_path = '/etc/docker/daemon.json'
  if file(daemon_json_path).exist?
    describe json(daemon_json_path) do
      its(['log-level']) { should eq "info" }
    end
  else
    describe 'CIS Docker daemon.json key log-level' do
      skip "host_daemon mode: /etc/docker/daemon.json not present — daemon is running with default flags. Operator confirms `dockerd --log-level` flag from process inventory."
    end
  end
  end
end
