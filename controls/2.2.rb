# encoding: UTF-8

control 'C-2.2' do
  title 'Ensure network traffic is restricted between containers on the default bridge'
  desc  "
    By default, all network traffic is allowed between containers on the same host on the default network bridge. If not desired, restrict all inter-container communication. Link specific containers together that require communication. Alternatively, you can create custom network and only join containers that need to communicate to that custom network.

    By default, unrestricted network traffic is enabled between all containers on the same host on the default network bridge. Thus, each container has the potential of reading all packets across the container network on the same host. This might lead to an unintended and unwanted disclosure of information to other containers. Hence, restrict inter-container communication on the default network bridge.
  "
  desc  'rationale', "
    By default, all network traffic is allowed between containers on the same host on the default network bridge. If not desired, restrict all inter-container communication. Link specific containers together that require communication. Alternatively, you can create custom network and only join containers that need to communicate to that custom network.

    By default, unrestricted network traffic is enabled between all containers on the same host on the default network bridge. Thus, each container has the potential of reading all packets across the container network on the same host. This might lead to an unintended and unwanted disclosure of information to other containers. Hence, restrict inter-container communication on the default network bridge.
  "
  desc  'check', "
    Run the below command and verify that the default network bridge has been configured to restrict inter-container communication.

    ```
    docker network ls --quiet | xargs docker network inspect --format '{{ .Name }}: {{ .Options }}' 
    ```

    It should return `com.docker.network.bridge.enable_icc:false` for the default network bridge.
  "
  desc  'fix', "
    Edit the Docker daemon configuration file to ensure that icc is disabled. It should include the following setting 

    ```
    \"icc\": false
    ```

    Alernatively, run the docker daemon directly and pass `--icc=false` as an argument.

    For Example,
    ```
    dockerd --icc=false
    ```

    Alternatively, you can follow the Docker documentation and create a custom network and only join containers that need to communicate to that custom network. The `--icc` parameter only applies to the default docker bridge, if custom networks are used then the approach of segmenting networks should be adopted instead.

    In order for this control to be fully effective, all containers connected to the `docker0` bridge should drop the `NET_RAW` capability, otherwise a compromised container could use raw ethernet packets to communicate with other containers despite this restriction.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-23']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT', 'KSI-SVC-SIN', 'KSI-SVC-VCM', 'KSI-SVC-VRI']
  tag nist_r4:               ['SC-23']
  tag cci:                   ['CCI-001184']
  tag cis_number:            '2.2'
  tag cis_rid:               '2.2'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0202r1_rule'
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
      its(['icc']) { should eq false }
    end
  else
    describe 'CIS Docker daemon.json key icc' do
      skip "host_daemon mode: /etc/docker/daemon.json not present — daemon is running with default flags. Operator confirms `dockerd --icc` flag from process inventory."
    end
  end
  end
end
