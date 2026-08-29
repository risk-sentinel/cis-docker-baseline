# encoding: UTF-8

control 'C-5.27' do
  title 'Ensure that container health is checked at runtime'
  desc  "
    If the container image does not have an `HEALTHCHECK` instruction defined, you should use the `--health-cmd` parameter at container runtime to check container health.

    If the container image you are using does not have a pre-defined `HEALTHCHECK` instruction, use the `--health-cmd` parameter to check container health at runtime.

    Based on the reported health status, remedial actions can be taken if necessary.
  "
  desc  'rationale', "
    If the container image does not have an `HEALTHCHECK` instruction defined, you should use the `--health-cmd` parameter at container runtime to check container health.

    If the container image you are using does not have a pre-defined `HEALTHCHECK` instruction, use the `--health-cmd` parameter to check container health at runtime.

    Based on the reported health status, remedial actions can be taken if necessary.
  "
  desc  'check', "
    You should run the command below and ensure that all containers are reporting their health status:
    ```
    docker ps --quiet | xargs docker inspect --format '{{ .Id }}: Health={{ .State.Health.Status }}' 
    ```
  "
  desc  'fix', "
    You should run the container using the `--health-cmd` parameter.

    For example:
    ```
    docker run -d --health-cmd='stat /etc/passwd || exit 1' nginx
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SI-12', 'SI-16']
  tag ksi:                   ['KSI-CNA-MAT', 'KSI-PIY-RSD', 'KSI-RPL-ABO']
  tag nist_r4:               ['SI-12', 'SI-16']
  tag cci:                   ['CCI-001315', 'CCI-002823']
  tag cis_number:            '5.27'
  tag cis_rid:               '5.27'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0527r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  uri = input('c_5_27_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-5.27') if uri.to_s.empty?
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (runtime health-check status is observable from `docker inspect` only; operators cross-reference CIS Docker §4.6 (HEALTHCHECK in image) and the task-definition healthCheck field) [Lift: set boundary_docs_base / c_5_27_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: input('attestation_max_age_days', value: 365))
    describe "Boundary policy attestation (C-5.27) (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current") { expect(doc.current?).to eq(true) }
    end
  end
end
