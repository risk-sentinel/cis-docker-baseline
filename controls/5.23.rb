# encoding: UTF-8

control 'C-5.23' do
  title 'Ensure that  docker exec commands are not used with the privileged option'
  desc  "
    You should not use `docker exec` with the `--privileged` option.

    Using the `--privileged` option in `docker exec` commands gives extended Linux capabilities to the command. This could potentially be an insecure practice, particularly when you are running containers with reduced capabilities or with enhanced restrictions.
  "
  desc  'rationale', "
    You should not use `docker exec` with the `--privileged` option.

    Using the `--privileged` option in `docker exec` commands gives extended Linux capabilities to the command. This could potentially be an insecure practice, particularly when you are running containers with reduced capabilities or with enhanced restrictions.
  "
  desc  'check', "
    If you have auditing enabled as recommended in Section 1, you can use the command below to filter out `docker exec` commands that use the `--privileged` option.
    ```
    ausearch -k docker | grep exec | grep privileged
    ```
  "
  desc  'fix', "
    You should not use the `--privileged` option in `docker exec` commands.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 c']
  tag nist_r4:               ['AC-2 c']
  tag cci:                   ['CCI-002113']
  tag cis_number:            '5.23'
  tag cis_rid:               '5.23'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0523r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  uri = input('c_5_23_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-5.23') if uri.to_s.empty?
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (docker exec --privileged usage is observable only from daemon audit logs; operators attest from CloudTrail ECS exec-command audit events on Fargate) [Lift: set boundary_docs_base / c_5_23_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: input('attestation_max_age_days', value: 365))
    describe "Boundary policy attestation (C-5.23) (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current") { expect(doc.current?).to eq(true) }
    end
  end
end
