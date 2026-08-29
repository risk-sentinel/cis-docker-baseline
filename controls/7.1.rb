# encoding: UTF-8

control 'C-7.1' do
  title 'Ensure that the minimum number of manager nodes have been created in a swarm'
  desc  "
    You should ensure that the minimum number of required manager nodes is created in a swarm.

    Manager nodes within a swarm have control over the swarm and can change its configuration, including modifying security parameters. Having excessive manager nodes could render the swarm more susceptible to compromise.

    If fault tolerance is not required in the manager nodes, a single node should be elected as a manger. If fault tolerance is required then the smallest odd number to achieve the appropriate level of tolerance should be configured.  This should always be an odd number in order to ensure that a quorum is reached.
  "
  desc  'rationale', "
    You should ensure that the minimum number of required manager nodes is created in a swarm.

    Manager nodes within a swarm have control over the swarm and can change its configuration, including modifying security parameters. Having excessive manager nodes could render the swarm more susceptible to compromise.

    If fault tolerance is not required in the manager nodes, a single node should be elected as a manger. If fault tolerance is required then the smallest odd number to achieve the appropriate level of tolerance should be configured.  This should always be an odd number in order to ensure that a quorum is reached.
  "
  desc  'check', "
    Run `docker info` and verify the number of managers.
    ```
    docker info --format '{{ .Swarm.Managers }}' 
    ```
    Alternatively run the below command.
    ```
    docker node ls | grep 'Leader' 
    ```
  "
  desc  'fix', "
    If an excessive number of managers is configured, the excess nodes can be demoted to workers using the following command:
    ```
    docker node demote ```
    Where is the node ID value of the manager to be demoted.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 a']
  tag nist_r4:               ['AC-2 a']
  tag cci:                   ['CCI-002110']
  tag cis_number:            '7.1'
  tag cis_rid:               '7.1'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0701r1_rule'
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
    describe "CIS Docker 7.1 — Swarm minimum manager-node count" do
      skip "not-applicable: AWS Fargate uses ECS scheduling; Docker Swarm is not running and has no manager-node count."
    end
  else
    describe 'Requires manual review and attestation' do
    skip "Requires manual review and attestation provided for this control (\"minimum manager nodes\" depends on consumer cluster sizing (CIS recommends >=3 for fault tolerance); operators attest from their swarm topology record)"
  end
  end
end
