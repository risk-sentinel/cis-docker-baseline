# encoding: UTF-8

control 'C-5.24' do
  title 'Ensure that docker exec commands are not used with the user=root option'
  desc  "
    You should not use `docker exec` with the `--user=root` option.

    Using the `--user=root` option in a `docker exec` command, executes it within the container as the root user. This could potentially be insecure, particularly when you are running containers with reduced capabilities or enhanced restrictions.

    For example, if your container is running as a tomcat user (or any other non-root user), it would be possible to run a command through `docker exec` as `root `with the `--user=root` option. This could potentially be dangerous.
  "
  desc  'rationale', "
    You should not use `docker exec` with the `--user=root` option.

    Using the `--user=root` option in a `docker exec` command, executes it within the container as the root user. This could potentially be insecure, particularly when you are running containers with reduced capabilities or enhanced restrictions.

    For example, if your container is running as a tomcat user (or any other non-root user), it would be possible to run a command through `docker exec` as `root `with the `--user=root` option. This could potentially be dangerous.
  "
  desc  'check', "
    If you have auditing enabled as recommended in Section 1, you can use the command below to filter out `docker exec` commands that use the `--user=root` option.
    ```
    ausearch -k docker | grep exec | grep user
    ```
  "
  desc  'fix', "
    You should not use the `--user=root` option in `docker exec` commands.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 c']
  tag cci:                   ['CCI-002113']
  tag cis_number:            '5.24'
  tag cis_rid:               '5.24'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0524r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  uri = input('c_5_24_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-5.24') if uri.to_s.empty?
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (docker exec --user=root usage is observable only from daemon audit logs; operators attest from CloudTrail ECS exec-command audit events) [Lift: set boundary_docs_base / c_5_24_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: input('attestation_max_age_days', value: 365))
    describe "Boundary policy attestation (C-5.24) (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current") { expect(doc.current?).to eq(true) }
    end
  end
end
