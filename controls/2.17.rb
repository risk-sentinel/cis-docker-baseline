# encoding: UTF-8

control 'C-2.17' do
  title 'Ensure Userland Proxy is Disabled'
  desc  "
    The Docker daemon starts a userland proxy service for port forwarding whenever a port is exposed. Where hairpin NAT is available, this service is generally superfluous to requirements and can be disabled.

    The Docker engine provides two mechanisms for forwarding ports from the host to containers, hairpin NAT, and the use of a userland proxy. In most circumstances, the hairpin NAT mode is preferred as it improves performance and makes use of native Linux iptables functionality instead of using an additional component.

    Where hairpin NAT is available, the userland proxy should be disabled on startup to reduce the attack surface of the installation.
  "
  desc  'rationale', "
    The Docker daemon starts a userland proxy service for port forwarding whenever a port is exposed. Where hairpin NAT is available, this service is generally superfluous to requirements and can be disabled.

    The Docker engine provides two mechanisms for forwarding ports from the host to containers, hairpin NAT, and the use of a userland proxy. In most circumstances, the hairpin NAT mode is preferred as it improves performance and makes use of native Linux iptables functionality instead of using an additional component.

    Where hairpin NAT is available, the userland proxy should be disabled on startup to reduce the attack surface of the installation.
  "
  desc  'check', "
    To confirm this setting, you should review the dockerd start-up options and any settings in `/etc/docker/daemon.json`.

    To review the dockerd startup options, use:
    ```
    ps -ef | grep dockerd 
    ```
    Ensure that the `--userland-proxy` parameter is set to `false`.

    The contents of `/etc/docker/daemon.json` should also be reviewed for this setting.
  "
  desc  'fix', "
    You should run the Docker daemon as below:
    ```
    dockerd --userland-proxy=false
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag nist_r4:               ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_number:            '2.17'
  tag cis_rid:               '2.17'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0217r1_rule'
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
      its(['userland-proxy']) { should eq false }
    end
  else
    describe 'CIS Docker daemon.json key userland-proxy' do
      skip "host_daemon mode: /etc/docker/daemon.json not present — daemon is running with default flags. Operator confirms `dockerd --userland-proxy` flag from process inventory."
    end
  end
  end
end
