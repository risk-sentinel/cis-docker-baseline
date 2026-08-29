# encoding: UTF-8

control 'C-7.7' do
  title 'Ensure that node certificates are rotated as appropriate'
  desc  "
    You should rotate swarm node certificates in line with your organizational security policy.

    Docker Swarm uses TLS for clustering operations between its nodes. Certificate rotation ensures that in an event such as a compromised node or key, it is difficult to impersonate a node. By default, node certificates are rotated every 90 days, but you should rotate them more often or as appropriate in your environment.
  "
  desc  'rationale', "
    You should rotate swarm node certificates in line with your organizational security policy.

    Docker Swarm uses TLS for clustering operations between its nodes. Certificate rotation ensures that in an event such as a compromised node or key, it is difficult to impersonate a node. By default, node certificates are rotated every 90 days, but you should rotate them more often or as appropriate in your environment.
  "
  desc  'check', "
    Run one of the commands below and ensure that the node certificate `Expiry Duration` is set as appropriate.
    ```
    docker info | grep \"Expiry Duration\"
    ```
    ```
    docker info --format 'NodeCertExpiry: {{ .Swarm.Cluster.Spec.CAConfig.NodeCertExpiry }}'
    ```
  "
  desc  'fix', "
    You should run the command to set the desired expiry time on the node certificate.

    For example:
    ```
    docker swarm update --cert-expiry 48h
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-7 a', 'IA-5 (1) (e)']
  tag cci:                   ['CCI-001097', 'CCI-000200']
  tag cis_number:            '7.7'
  tag cis_rid:               '7.7'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0707r1_rule'
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
    describe "CIS Docker 7.7 — node certificates rotated as appropriate" do
      skip "not-applicable: AWS Fargate uses ECS scheduling; no Swarm node certificates issued."
    end
  else
    describe 'Requires manual review and attestation' do
    skip "Requires manual review and attestation provided for this control (node-cert rotation cadence is operational policy; default 90-day rotation is acceptable per CIS — operators attest the running configuration)"
  end
  end
end
