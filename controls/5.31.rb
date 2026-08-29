# encoding: UTF-8

control 'C-5.31' do
  title 'Ensure that the host\'s user namespaces are not shared'
  desc  "
    You should not share the host's user namespaces with containers running on it.

    User namespaces ensure that a root process inside the container will be mapped to a non-root process outside the container. Sharing the user namespaces of the host with the container does not therefore isolate users on the host from users in the containers.
  "
  desc  'rationale', "
    You should not share the host's user namespaces with containers running on it.

    User namespaces ensure that a root process inside the container will be mapped to a non-root process outside the container. Sharing the user namespaces of the host with the container does not therefore isolate users on the host from users in the containers.
  "
  desc  'check', "
    You should run the command below and ensure that it does not return any value for `UsernsMode`. If it returns a value of `host`, it means that the host user namespace is shared with its containers.

    ```
    docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: UsernsMode={{ .HostConfig.UsernsMode }}'
    ```
  "
  desc  'fix', "
    You should not share user namespaces between host and containers.

    For example, you should not run the command below:
    ```
    docker run --rm -it --userns=host ubuntu bash
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-8 a']
  tag cci:                   ['CCI-000051']
  tag cis_number:            '5.31'
  tag cis_rid:               '5.31'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0531r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  uri = input('c_5_31_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-5.31') if uri.to_s.empty?
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (host user namespace sharing is detectable from task-definition --userns=host; not visible from inside the container without host-namespace comparison) [Lift: set boundary_docs_base / c_5_31_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: input('attestation_max_age_days', value: 365))
    describe "Boundary policy attestation (C-5.31) (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current") { expect(doc.current?).to eq(true) }
    end
  end
end
