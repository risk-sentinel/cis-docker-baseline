# encoding: UTF-8

control 'C-2.8' do
  title 'Ensure TLS authentication for Docker daemon is configured'
  desc  "
    It is possible to make the Docker daemon available remotely over a TCP port. If this is required, you should ensure that TLS authentication is configured in order to restrict access to the Docker daemon via IP address and port.

    By default, the Docker daemon binds to a non-networked Unix socket and runs with `root` privileges. If you change the default Docker daemon binding to a TCP port or any other Unix socket, anyone with access to that port or socket could have full access to the Docker daemon and therefore in turn to the host system. For this reason, you should not bind the Docker daemon to another IP/port or a Unix socket.

    If you must expose the Docker daemon via a network socket, you should configure TLS authentication for the daemon and for any Docker Swarm APIs (if they are in use). This type of configuration restricts the connections to your Docker daemon over the network to a limited number of clients who have access to the TLS client credentials.
  "
  desc  'rationale', "
    It is possible to make the Docker daemon available remotely over a TCP port. If this is required, you should ensure that TLS authentication is configured in order to restrict access to the Docker daemon via IP address and port.

    By default, the Docker daemon binds to a non-networked Unix socket and runs with `root` privileges. If you change the default Docker daemon binding to a TCP port or any other Unix socket, anyone with access to that port or socket could have full access to the Docker daemon and therefore in turn to the host system. For this reason, you should not bind the Docker daemon to another IP/port or a Unix socket.

    If you must expose the Docker daemon via a network socket, you should configure TLS authentication for the daemon and for any Docker Swarm APIs (if they are in use). This type of configuration restricts the connections to your Docker daemon over the network to a limited number of clients who have access to the TLS client credentials.
  "
  desc  'check', "
    To confirm this setting, review the dockerd start-up options and any settings in `/etc/docker/daemon.json`.

    To review the dockerd startup options, use:
    ```
    grep \"--tls\" /etc/docker/daemon.json
    ```
    Ensure that the below parameters are present:

    ```
    --tlsverify
    --tlscacert
    --tlscert
    --tlskey
    ```


    The contents of `/etc/docker/daemon.json` to ensure these settings are in place.
  "
  desc  'fix', "
    Follow the steps mentioned in the Docker documentation or other references.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SI-4 (11)', 'AC-17 (2)']
  tag nist_r4:               ['AC-17 (2)', 'SI-4 (11)']
  tag cci:                   ['CCI-002668', 'CCI-000068']
  tag cis_number:            '2.8'
  tag cis_rid:               '2.8'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0208r1_rule'
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
  describe file(daemon_json_path) do
    it { should exist }
  end
  if file(daemon_json_path).exist?
    describe json(daemon_json_path) do
      its(['tlsverify']) { should eq true }
      its(['tlscacert']) { should_not be_nil }
      its(['tlscert'])   { should_not be_nil }
      its(['tlskey'])    { should_not be_nil }
    end
  end
  end
end
