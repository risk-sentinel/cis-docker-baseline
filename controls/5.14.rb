# encoding: UTF-8

control 'C-5.14' do
  title 'Ensure that incoming container traffic is bound to a specific host interface'
  desc  "
    By default, Docker containers can make connections to the outside world, but the outside world cannot connect to containers and each outgoing connection will appear to originate from one of the host machine's own IP addresses. You should only allow container services to be contacted through a specific external interface on the host machine.

    If you have multiple network interfaces on your host machine, the container can accept connections on exposed ports on any network interface. This might not be desirable and may not be secured. In many cases a specific, desired interface is exposed externally and services such as intrusion detection, intrusion prevention, firewall, load balancing, etc. are all run by intention there to screen incoming public traffic. You should therefore not accept incoming connections on any random interface, but only the one designated for this type of traffic.
  "
  desc  'rationale', "
    By default, Docker containers can make connections to the outside world, but the outside world cannot connect to containers and each outgoing connection will appear to originate from one of the host machine's own IP addresses. You should only allow container services to be contacted through a specific external interface on the host machine.

    If you have multiple network interfaces on your host machine, the container can accept connections on exposed ports on any network interface. This might not be desirable and may not be secured. In many cases a specific, desired interface is exposed externally and services such as intrusion detection, intrusion prevention, firewall, load balancing, etc. are all run by intention there to screen incoming public traffic. You should therefore not accept incoming connections on any random interface, but only the one designated for this type of traffic.
  "
  desc  'check', "
    You should list all running instances of containers and their port mappings by executing the command below:

    ```
    docker ps --quiet | xargs docker inspect --format '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}'
    ```

    Then review the list and ensure that the exposed container ports are bound to a specific interface and not to the wildcard IP address `0.0.0.0`.

    For example, if the command above returns the results below, this is non-compliant and the container can accept connections on any host interface on the specified port `49153`.

    `Ports=map[443/tcp: 80/tcp:[map[HostPort:49153 HostIp:0.0.0.0]]]`

    However, if the exposed port is bound to a specific interface on the host as below, then this is configured in line with good security practice.

    `Ports=map[443/tcp: 80/tcp:[map[HostIp:10.2.3.4 HostPort:49153]]]`
  "
  desc  'fix', "
    You should bind the container port to a specific host interface on the desired host port.

    For example,
    ```
    docker run --detach --publish 10.2.3.4:49153:80 nginx
    ```
    In the example above, the container port `80` is bound to the host port on `49153` and would accept incoming connection only from the `10.2.3.4` external interface.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-7 a']
  tag ksi:                   ['KSI-CNA-ULN', 'KSI-SVC-EIS']
  tag nist_r4:               ['SC-7 a']
  tag cci:                   ['CCI-001097']
  tag cis_number:            '5.14'
  tag cis_rid:               '5.14'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0514r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  uri = input('c_5_14_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-5.14') if uri.to_s.empty?
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (binding incoming traffic to a specific host interface is set in task-definition portMappings hostPort + ALB target-group attachment; not visible from inside the container — operators attest from the network architecture record) [Lift: set boundary_docs_base / c_5_14_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: input('attestation_max_age_days', value: 365))
    describe "Boundary policy attestation (C-5.14) (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current") { expect(doc.current?).to eq(true) }
    end
  end
end
