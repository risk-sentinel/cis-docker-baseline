# encoding: UTF-8

control 'C-5.8' do
  title 'Ensure privileged ports are not mapped within containers'
  desc  "
    The TCP/IP port numbers below `1024 `are considered privileged ports. Normal users and processes are not allowed to use them for various security reasons. Docker does, however allow a container port to be mapped to a privileged port.

    By default, if the user does not specifically declare a container port to host port mapping, Docker automatically and correctly maps the container port to one available in the `49153-65535` range on the host. Docker does, however, allow a container port to be mapped to a privileged port on the host if the user explicitly declares it. This is because containers are executed with `NET_BIND_SERVICE` Linux kernel capability which does not restrict privileged port mapping. The privileged ports receive and transmit various pieces of data which are security sensitive and allowing containers to use them is not in line with good security practice.
  "
  desc  'rationale', "
    The TCP/IP port numbers below `1024 `are considered privileged ports. Normal users and processes are not allowed to use them for various security reasons. Docker does, however allow a container port to be mapped to a privileged port.

    By default, if the user does not specifically declare a container port to host port mapping, Docker automatically and correctly maps the container port to one available in the `49153-65535` range on the host. Docker does, however, allow a container port to be mapped to a privileged port on the host if the user explicitly declares it. This is because containers are executed with `NET_BIND_SERVICE` Linux kernel capability which does not restrict privileged port mapping. The privileged ports receive and transmit various pieces of data which are security sensitive and allowing containers to use them is not in line with good security practice.
  "
  desc  'check', "
    You can list all running containers instances and their port mappings by executing the command below:

    ```
    docker ps --quiet | xargs docker inspect --format '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}'
    ```

    You should then review the list and ensure that container ports are not mapped to host port numbers below `1024`.
  "
  desc  'fix', "
    You should not map container ports to privileged host ports when starting a container. You should also, ensure that there is no such container to host privileged port mapping declarations in the Dockerfile.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SI-4 (11)', 'AC-17 (1)']
  tag cci:                   ['CCI-002668', 'CCI-000067']
  tag cis_number:            '5.8'
  tag cis_rid:               '5.8'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0508r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  uri = input('c_5_8_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-5.8') if uri.to_s.empty?
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (privileged-port mapping (host port < 1024) is configured at the orchestration layer — task definition portMappings on ECS, container ports on Kubernetes, `--publish` flags on raw docker run — and is not observable from inside the container itself. Operator attests from the port-mapping inventory in the orchestrator's spec.) [Lift: set boundary_docs_base / c_5_8_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: input('attestation_max_age_days', value: 365))
    describe "Boundary policy attestation (C-5.8) (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current") { expect(doc.current?).to eq(true) }
    end
  end
end
