# encoding: UTF-8

control 'C-4.6' do
  title 'Ensure that HEALTHCHECK instructions have been added to container images'
  desc  "
    You should add the `HEALTHCHECK` instruction to your Docker container images in order to ensure that health checks are executed against running containers.

    An important security control is that of availability. Adding the `HEALTHCHECK` instruction to your container image ensures that the Docker engine periodically checks the running container instances against that instruction to ensure that containers are still operational.

    Based on the results of the health check, the Docker engine could terminate containers which are not responding correctly, and instantiate new ones.
  "
  desc  'rationale', "
    You should add the `HEALTHCHECK` instruction to your Docker container images in order to ensure that health checks are executed against running containers.

    An important security control is that of availability. Adding the `HEALTHCHECK` instruction to your container image ensures that the Docker engine periodically checks the running container instances against that instruction to ensure that containers are still operational.

    Based on the results of the health check, the Docker engine could terminate containers which are not responding correctly, and instantiate new ones.
  "
  desc  'check', "
    You should run the command below to ensure that Docker images have the appropriate `HEALTHCHECK` instruction configured.

    ```
    docker inspect --format='{{ .Config.Healthcheck }}' ```
  "
  desc  'fix', "
    You should follow the Docker documentation and rebuild your container images to include the `HEALTHCHECK` instruction.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['IA-5 (1) (e)', 'SA-11 a']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-SCR-MIT']
  tag nist_r4:               ['IA-5 (1) (e)', 'SA-11 a']
  tag cci:                   ['CCI-000200', 'CCI-003171']
  tag cis_number:            '4.6'
  tag cis_rid:               '4.6'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0406r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  uri = input('c_4_6_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-4.6') if uri.to_s.empty?
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (HEALTHCHECK is set in the image config (Dockerfile HEALTHCHECK directive) and is not visible from inside a running container without docker-daemon access; host_daemon scans can iterate `docker inspect` to verify presence — operators on Fargate attest from their image-build inventory) [Lift: set boundary_docs_base / c_4_6_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: input('attestation_max_age_days', value: 365))
    describe "Boundary policy attestation (C-4.6) (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current") { expect(doc.current?).to eq(true) }
    end
  end
end
