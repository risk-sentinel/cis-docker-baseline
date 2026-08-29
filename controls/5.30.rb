# encoding: UTF-8

control 'C-5.30' do
  title 'Ensure that Docker\'s default bridge "docker0" is not used'
  desc  "
    You should not use Docker's default bridge `docker0`. Instead you should use Docker's user-defined networks for container networking.

    Docker connects virtual interfaces created in bridge mode to a common bridge called `docker0`. This default networking model is vulnerable to ARP spoofing and MAC flooding attacks as there is no filtering applied to it.
  "
  desc  'rationale', "
    You should not use Docker's default bridge `docker0`. Instead you should use Docker's user-defined networks for container networking.

    Docker connects virtual interfaces created in bridge mode to a common bridge called `docker0`. This default networking model is vulnerable to ARP spoofing and MAC flooding attacks as there is no filtering applied to it.
  "
  desc  'check', "
    You should run the command below, and verify that containers are on a user-defined network and not the default `docker0` bridge.
    ```
    docker network ls --quiet | xargs docker network inspect --format '{{ .Name }}: {{ .Options }}' 
    ```
  "
  desc  'fix', "
    You should follow the Docker documentation and set up a user-defined network. All the containers should be run in this network.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-7 a']
  tag nist_r4:               ['CM-7 a']
  tag cci:                   ['CCI-000381']
  tag cis_number:            '5.30'
  tag cis_rid:               '5.30'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0530r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  uri = input('c_5_30_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-5.30') if uri.to_s.empty?
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (default docker0 bridge usage is detectable only from daemon-side network configuration; Fargate doesn't expose a Docker bridge network) [Lift: set boundary_docs_base / c_5_30_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: input('attestation_max_age_days', value: 365))
    describe "Boundary policy attestation (C-5.30) (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current") { expect(doc.current?).to eq(true) }
    end
  end
end
