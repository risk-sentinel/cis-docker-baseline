# encoding: UTF-8

control 'C-2.10' do
  title 'Enable user namespace support'
  desc  "
    You should enable user namespace support in Docker daemon to utilize container user to host user re-mapping. This recommendation is beneficial where the containers you are using do not have an explicit container user defined in the container image. If the container images that you are using have a pre-defined non-root user, this recommendation may be skipped as this feature is still in its infancy, and might result in unpredictable issues or difficulty in configuration.

    The Linux kernel \"user namespace\" support within the Docker daemon provides additional security for the Docker host system. It allows a container to have a unique range of user and group IDs which are outside the traditional user and group range utilized by the host system.

    For example, the root user can have the expected administrative privileges inside the container but can effectively be mapped to an unprivileged UID on the host system.
  "
  desc  'rationale', "
    You should enable user namespace support in Docker daemon to utilize container user to host user re-mapping. This recommendation is beneficial where the containers you are using do not have an explicit container user defined in the container image. If the container images that you are using have a pre-defined non-root user, this recommendation may be skipped as this feature is still in its infancy, and might result in unpredictable issues or difficulty in configuration.

    The Linux kernel \"user namespace\" support within the Docker daemon provides additional security for the Docker host system. It allows a container to have a unique range of user and group IDs which are outside the traditional user and group range utilized by the host system.

    For example, the root user can have the expected administrative privileges inside the container but can effectively be mapped to an unprivileged UID on the host system.
  "
  desc  'check', "
    ```
    docker inspect --format='{{ .State.Pid }}' $(docker ps -q) | while read -r line; do ps -h -p \"$line\" -o pid,user; done
    ```
    The above command will find the PID of the container and then list the host user associated with the container process. If the container process is running as `root,` then this configuration may be non-compliant with your organization's security policy.

    Alternatively, you can run `docker info` to ensure that the `userns` is listed under `Security Options:`
    ```
    docker info --format '{{ .SecurityOptions }}' 
    ```
  "
  desc  'fix', "
    Please consult the Docker documentation for various ways in which this can be configured depending upon your requirements. Your steps might also vary based on platform - For example, on Red Hat, sub-UIDs and sub-GIDs mapping creation do not work automatically. You might have to create your own mapping.

    The high-level steps are as below:

    Step 1: Ensure that the files `/etc/subuid` and `/etc/subgid` exist.
    ```
    touch /etc/subuid /etc/subgid 
    ```
    Step 2: Start the docker daemon with `--userns-remap` flag
    ```
    dockerd --userns-remap=default
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '2.10'
  tag cis_rid:               '2.10'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0210r1_rule'
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
      its(['userns-remap']) { should_not be_nil }
    end
  else
    describe 'CIS Docker daemon.json key userns-remap' do
      skip "host_daemon mode: /etc/docker/daemon.json not present — daemon is running with default flags. Operator confirms `dockerd --userns-remap` flag from process inventory."
    end
  end
  end
end
