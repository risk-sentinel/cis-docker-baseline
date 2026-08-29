# encoding: UTF-8

control 'C-5.1' do
  title 'Ensure swarm mode is not Enabled, if not needed'
  desc  "
    Do not enable swarm mode on a Docker engine instance unless this is needed.

    By default, a Docker engine instance will not listen on any network ports, with all communications with the client coming over the Unix socket. When Docker swarm mode is enabled on a Docker engine instance, multiple network ports are opened on the system and made available to other systems on the network for the purposes of cluster management and node communications.

    Opening network ports on a system increases its attack surface and this should be avoided unless required.

    It should be noted that swarm mode is required for the operation of Docker Enterprise components.
  "
  desc  'rationale', "
    Do not enable swarm mode on a Docker engine instance unless this is needed.

    By default, a Docker engine instance will not listen on any network ports, with all communications with the client coming over the Unix socket. When Docker swarm mode is enabled on a Docker engine instance, multiple network ports are opened on the system and made available to other systems on the network for the purposes of cluster management and node communications.

    Opening network ports on a system increases its attack surface and this should be avoided unless required.

    It should be noted that swarm mode is required for the operation of Docker Enterprise components.
  "
  desc  'check', "
    Review the output of 
    ```
    docker info --format '{{ .Swarm }}'
    ```

    If the output includes `active true` it indicates that swarm mode has been activated on the Docker engine. In this case, you should confirm if swarm mode on the Docker engine instance is actually needed.
  "
  desc  'fix', "
    If swarm mode has been enabled on a system in error, you should run the command below:
    ```
    docker swarm leave
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag ksi:                   ['KSI-CMT-RMV', 'KSI-IAM-JIT']
  tag nist_r4:               ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_number:            '5.1'
  tag cis_rid:               '5.1'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0501r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  uri = input('c_5_1_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-5.1') if uri.to_s.empty?
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (Docker Swarm mode is not used on AWS Fargate (ECS scheduling instead) — covered separately by §7 not-applicable. Host_daemon consumers attest from `docker info` output) [Lift: set boundary_docs_base / c_5_1_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: input('attestation_max_age_days', value: 365))
    describe "Boundary policy attestation (C-5.1) (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current") { expect(doc.current?).to eq(true) }
    end
  end
end
