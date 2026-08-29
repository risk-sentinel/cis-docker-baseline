# encoding: UTF-8

control 'C-7.4' do
  title 'Ensure that Docker\'s secret management commands are used for managing secrets in a swarm cluster'
  desc  "
    You should use Docker's in-built secret management command for control of secrets.

    Docker has various commands for managing secrets in a swarm cluster.
  "
  desc  'rationale', "
    You should use Docker's in-built secret management command for control of secrets.

    Docker has various commands for managing secrets in a swarm cluster.
  "
  desc  'check', "
    On a swarm manager node, you should run the command below and ensure `docker secret` management is used in your environment where this is in line with your IT security policy.
    ```
    docker secret ls
    ```
  "
  desc  'fix', "
    You should follow the `docker secret` documentation and use it to manage secrets effectively.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 a']
  tag nist_r4:               ['AC-2 a']
  tag cci:                   ['CCI-002110']
  tag cis_number:            '7.4'
  tag cis_rid:               '7.4'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0704r1_rule'
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
    describe "CIS Docker 7.4 — Docker secret management used for swarm secrets" do
      skip "not-applicable: AWS Fargate uses ECS scheduling; consumers typically manage secrets via AWS Secrets Manager + task-definition `secrets` references."
    end
  else
    describe 'Requires manual review and attestation' do
    skip "Requires manual review and attestation provided for this control (use of `docker secret` is consumer-policy-specific; operators attest from their secret-management process)"
  end
  end
end
