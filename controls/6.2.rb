# encoding: UTF-8

control 'C-6.2' do
  title 'Ensure that container sprawl is avoided'
  desc  "
    You should not keep a large number of containers on the same host.

    The flexibility of containers makes it easy to run multiple instances of applications and therefore indirectly leads to Docker images that can exist at varying security patch levels. It also means that you are consuming host resources that otherwise could have been used for running 'useful' containers. Having more than just an essential number of containers on a particular host makes the system vulnerable to mishandling, misconfiguration and fragmentation. You should therefore keep the number of containers on a given host to the minimum number commensurate with serving production applications.
  "
  desc  'rationale', "
    You should not keep a large number of containers on the same host.

    The flexibility of containers makes it easy to run multiple instances of applications and therefore indirectly leads to Docker images that can exist at varying security patch levels. It also means that you are consuming host resources that otherwise could have been used for running 'useful' containers. Having more than just an essential number of containers on a particular host makes the system vulnerable to mishandling, misconfiguration and fragmentation. You should therefore keep the number of containers on a given host to the minimum number commensurate with serving production applications.
  "
  desc  'check', "
    Step 1 - Find the total number of containers you have on the host:

    ```
    docker info --format '{{ .Containers }}' 
    ```

    Step 2 - Execute the commands below to find the total number of containers that are actually running or in the stopped state on the host.

    ```
    docker info --format '{{ .ContainersStopped }}' 
    docker info --format '{{ .ContainersRunning }}' 
    ```

    If the difference between the number of containers that are stopped on the host and the number of containers that are actually running is excessive, you may be suffering from \"Container sprawl\" and should review the unused containers for potential deletion.
  "
  desc  'fix', "
    You should periodically check your container inventory on each host and clean up containers which are not in active use with the command below:

    ```
    docker container prune
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 a']
  tag cci:                   ['CCI-002110']
  tag cis_number:            '6.2'
  tag cis_rid:               '6.2'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0602r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  uri = input('c_6_2_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-6.2') if uri.to_s.empty?
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (container sprawl avoidance is an operational control (regular `docker container prune`, ECS task-definition revision cleanup) — operators attest from their cleanup process) [Lift: set boundary_docs_base / c_6_2_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: input('attestation_max_age_days', value: 365))
    describe "Boundary policy attestation (C-6.2) (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current") { expect(doc.current?).to eq(true) }
    end
  end
end
