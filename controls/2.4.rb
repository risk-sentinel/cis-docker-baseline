# encoding: UTF-8

control 'C-2.4' do
  title 'Ensure Docker is allowed to make changes to iptables'
  desc  "
    The iptables firewall is used to set up, maintain, and inspect the tables of IP packet filter rules within the Linux kernel.  The Docker daemon should be allowed to make changes to the `iptables` ruleset.

    Docker will never make changes to your system `iptables ` rules unless you allow it to do so. If you do allow this, Docker server will automatically make any required changes. We recommended letting Docker make changes to `iptables `automatically in order to avoid networking misconfigurations that could affect the communication between containers and with the outside world. Additionally, this reduces the administrative overhead of updating `iptables `every time you add containers or modify networking options.
  "
  desc  'rationale', "
    The iptables firewall is used to set up, maintain, and inspect the tables of IP packet filter rules within the Linux kernel.  The Docker daemon should be allowed to make changes to the `iptables` ruleset.

    Docker will never make changes to your system `iptables ` rules unless you allow it to do so. If you do allow this, Docker server will automatically make any required changes. We recommended letting Docker make changes to `iptables `automatically in order to avoid networking misconfigurations that could affect the communication between containers and with the outside world. Additionally, this reduces the administrative overhead of updating `iptables `every time you add containers or modify networking options.
  "
  desc  'check', "
    To confirm this setting you should review the dockerd start-up options and the settings in `/etc/docker/daemon.json` 

    To review the dockerd startup options, use:
    ```
    grep \"--iptables\" /etc/docker/daemon.json
    ```
    Ensure that the `--iptables` parameter is either not present or not set to `false`.

    The contents of `/etc/docker/daemon.json` should also be reviewed for this setting.
  "
  desc  'fix', "
    Do not run the Docker daemon with `--iptables=false` parameter. For example, do not start the Docker daemon as below:
    ```
    dockerd --iptables=false
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SA-8']
  tag cci:                   ['CCI-000664']
  tag cis_number:            '2.4'
  tag cis_rid:               '2.4'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0204r1_rule'
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
      its(['iptables']) { should eq true }
    end
  else
    describe 'CIS Docker daemon.json key iptables' do
      skip "host_daemon mode: /etc/docker/daemon.json not present — daemon is running with default flags. Operator confirms `dockerd --iptables` flag from process inventory."
    end
  end
  end
end
