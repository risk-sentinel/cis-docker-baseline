# encoding: UTF-8

control 'C-5.10' do
  title 'Ensure that the host\'s network namespace is not shared'
  desc  "
    When the networking mode on a container is set to `--net=host`, the container is not placed inside a separate network stack. Effectively, applying this option instructs Docker to not containerize the container's networking. The consequence of this is that the container lives \"outside\" in the main Docker host and has full access to its network interfaces.

    Selecting this option is potentially dangerous. It allows the container process to open reserved low numbered ports in the way that any other `root` process can. It also allows the container to access network services such as D-bus on the Docker host.  A container process could potentially carry out undesired actions, such as shutting down the Docker host. This option should not be used unless there is a very specific reason for enabling it.
  "
  desc  'rationale', "
    When the networking mode on a container is set to `--net=host`, the container is not placed inside a separate network stack. Effectively, applying this option instructs Docker to not containerize the container's networking. The consequence of this is that the container lives \"outside\" in the main Docker host and has full access to its network interfaces.

    Selecting this option is potentially dangerous. It allows the container process to open reserved low numbered ports in the way that any other `root` process can. It also allows the container to access network services such as D-bus on the Docker host.  A container process could potentially carry out undesired actions, such as shutting down the Docker host. This option should not be used unless there is a very specific reason for enabling it.
  "
  desc  'check', "
    You should use the command below:

    ```
    docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: NetworkMode={{ .HostConfig.NetworkMode }}'
    ```
    If this returns `NetworkMode=host`, it means that the `--net=host` option was passed when the container was started.
  "
  desc  'fix', "
    You should not pass the `--net=host` option when starting any container.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SA-8']
  tag cci:                   ['CCI-000664']
  tag cis_number:            '5.10'
  tag cis_rid:               '5.10'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0510r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  uri = input('c_5_10_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-5.10') if uri.to_s.empty?
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (host network namespace sharing — networkMode=host on ECS, hostNetwork=true on Kubernetes, --network=host on docker run — is configured at the orchestration layer and is not visible from inside the container without host-namespace comparison. Operator attests from the orchestrator's spec.) [Lift: set boundary_docs_base / c_5_10_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: input('attestation_max_age_days', value: 365))
    describe "Boundary policy attestation (C-5.10) (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current") { expect(doc.current?).to eq(true) }
    end
  end
end
