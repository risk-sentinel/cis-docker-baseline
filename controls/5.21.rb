# encoding: UTF-8

control 'C-5.21' do
  title 'Ensure that the host\'s UTS namespace is not shared'
  desc  "
    UTS namespaces provide isolation between two system identifiers: the hostname and the NIS domain name. It is used to set the hostname and the domain which are visible to running processes in that namespace. Processes running within containers do not typically require to know either the hostname or the domain name. The UTS namespace should therefore not be shared with the host.

    Sharing the UTS namespace with the host provides full permission for each container to change the hostname of the host. This is not in line with good security practice and should not be permitted.
  "
  desc  'rationale', "
    UTS namespaces provide isolation between two system identifiers: the hostname and the NIS domain name. It is used to set the hostname and the domain which are visible to running processes in that namespace. Processes running within containers do not typically require to know either the hostname or the domain name. The UTS namespace should therefore not be shared with the host.

    Sharing the UTS namespace with the host provides full permission for each container to change the hostname of the host. This is not in line with good security practice and should not be permitted.
  "
  desc  'check', "
    You should run the following command:
    ```
    docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: UTSMode={{ .HostConfig.UTSMode }}' 
    ```
    If the above command returns `host`, it means the host UTS namespace is shared with the container and this recommendation is non-compliant. If the above command returns nothing, then the host's UTS namespace is not shared. This recommendation is then compliant.
  "
  desc  'fix', "
    You should not start a container with the `--uts=host` argument.

    For example, do not start a container using the command below:
    ```
    docker run --rm --interactive --tty --uts=host rhel7.2
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SI-4 (5)', 'AC-8 a']
  tag cci:                   ['CCI-002663', 'CCI-000051']
  tag cis_number:            '5.21'
  tag cis_rid:               '5.21'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0521r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  uri = input('c_5_21_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-5.21') if uri.to_s.empty?
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (host UTS namespace sharing is detectable from task-definition --uts=host; not visible from inside the container) [Lift: set boundary_docs_base / c_5_21_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: input('attestation_max_age_days', value: 365))
    describe "Boundary policy attestation (C-5.21) (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current") { expect(doc.current?).to eq(true) }
    end
  end
end
