# encoding: UTF-8

control 'C-7.9' do
  title 'Ensure that management plane traffic is separated from data plane traffic'
  desc  "
    You should separate management plane traffic from data plane traffic.

    Separating management plane traffic from data plane traffic ensures that these types of traffic are segregated from each other. These traffic flows can then be individually monitored and tied to different traffic control policies and monitoring. This also ensures that the management plane is always reachable even if there is a great deal of traffic on the data plane.
  "
  desc  'rationale', "
    You should separate management plane traffic from data plane traffic.

    Separating management plane traffic from data plane traffic ensures that these types of traffic are segregated from each other. These traffic flows can then be individually monitored and tied to different traffic control policies and monitoring. This also ensures that the management plane is always reachable even if there is a great deal of traffic on the data plane.
  "
  desc  'check', "
    You should run the command below on each swarm node and ensure that the management plane address is different from the data plane address.

    ```
    docker node inspect  --format '{{ .Status.Addr }}' self
    ```
  "
  desc  'fix', "
    You should initialize the swarm with dedicated interfaces for management and data planes respectively. 

    For example,
    ```
    docker swarm init --advertise-addr=192.168.0.1 --data-path-addr=17.1.0.3
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SI-4 (5)', 'AC-8 a']
  tag nist_r4:               ['SI-4 (5)']
  tag cci:                   ['CCI-002663', 'CCI-000051']
  tag cis_number:            '7.9'
  tag cis_rid:               '7.9'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0709r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  if input('docker_target_mode') == 'container_only'
    tag implementation_status: 'not-applicable'
  else
    tag implementation_status: 'alternative'
  end
  tag exec_validated:          false

  if input('docker_target_mode') == 'container_only'
    describe "CIS Docker 7.9 — management-plane traffic separated from data-plane" do
      skip "not-applicable: AWS Fargate uses ECS scheduling; no Swarm control-plane to segregate."
    end
  else
    describe 'Requires manual review and attestation' do
    skip "Requires manual review and attestation provided for this control (management-vs-data plane separation depends on the consumer's network design; operators attest from their network architecture record)"
  end
  end
end
