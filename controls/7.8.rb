# encoding: UTF-8

control 'C-7.8' do
  title 'Ensure that CA certificates are rotated as appropriate'
  desc  "
    You should rotate root CA certificates as appropriate.

    Docker Swarm uses TLS for clustering operations between its nodes. Certificate rotation ensures that in an event such as a compromised node or key, it is difficult to impersonate a node. Node certificates depend upon root CA certificates. For operational security, it is important to rotate these frequently. Currently, root CA certificates are not rotated automatically and you should therefore establish a process for rotating them in line with your organizational security policy.
  "
  desc  'rationale', "
    You should rotate root CA certificates as appropriate.

    Docker Swarm uses TLS for clustering operations between its nodes. Certificate rotation ensures that in an event such as a compromised node or key, it is difficult to impersonate a node. Node certificates depend upon root CA certificates. For operational security, it is important to rotate these frequently. Currently, root CA certificates are not rotated automatically and you should therefore establish a process for rotating them in line with your organizational security policy.
  "
  desc  'check', "
    You should check the time stamp on the root CA certificate file.

    For example:
    ```
    ls -l /var/lib/docker/swarm/certificates/swarm-root-ca.crt
    ```
    The certificate should show a time stamp in line with the organizational rotation policy.
  "
  desc  'fix', "
    You should run the command below to rotate a certificate.

    ```
    docker swarm ca --rotate
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-7 a', 'IA-5 (1) (e)']
  tag cci:                   ['CCI-001097', 'CCI-000200']
  tag cis_number:            '7.8'
  tag cis_rid:               '7.8'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0708r1_rule'
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
    describe "CIS Docker 7.8 — CA certificates rotated as appropriate" do
      skip "not-applicable: AWS Fargate uses ECS scheduling; no Swarm CA certificates to rotate."
    end
  else
    describe 'Requires manual review and attestation' do
    skip "Requires manual review and attestation provided for this control (CA-cert rotation is an event-driven control (compromise / personnel change); operators attest from their incident-response + key-management record)"
  end
  end
end
