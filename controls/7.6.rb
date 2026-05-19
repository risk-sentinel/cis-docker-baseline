# encoding: UTF-8

control 'C-7.6' do
  title 'Ensure that the swarm manager auto-lock key is rotated periodically'
  desc  "
    You should rotate the swarm manager auto-lock key periodically.

    The swarm manager auto-lock key is not automatically rotated. Good security practice is to rotate keys.
  "
  desc  'rationale', "
    You should rotate the swarm manager auto-lock key periodically.

    The swarm manager auto-lock key is not automatically rotated. Good security practice is to rotate keys.
  "
  desc  'check', "
    Currently, there is no mechanism to find out when the key was last rotated on a swarm manager node. You should check with the system administrator to see if there is a key rotation process, and how often the key is rotated.
  "
  desc  'fix', "
    You should run the command below to rotate the keys.
    ```
    docker swarm unlock-key --rotate
    ```
    Additionally, to facilitate auditing of this recommendation, you should maintain key rotation records and ensure that you establish a pre-defined frequency for key rotation.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-7 a', 'IA-5 (1) (e)']
  tag cci:                   ['CCI-001097', 'CCI-000200']
  tag cis_number:            '7.6'
  tag cis_rid:               '7.6'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0706r1_rule'
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
    describe "CIS Docker 7.6 — swarm manager auto-lock key rotated periodically" do
      skip "not-applicable: AWS Fargate uses ECS scheduling; no Swarm auto-lock key to rotate."
    end
  else
    describe 'Requires manual review and attestation' do
    skip "Requires manual review and attestation provided for this control (key-rotation cadence is operational policy; operators attest from their key-rotation runbook + audit log)"
  end
  end
end
