# encoding: UTF-8

control 'C-7.2' do
  title 'Ensure that swarm services are bound to a specific host interface'
  desc  "
    By default, Docker swarm services will listen on all interfaces on the host.  This may not be necessary for the operation of the swarm where the host has multiple network interfaces.

    When a swarm is initialized the default value for the `--listen-addr` flag is `0.0.0.0:2377` which means that swarm services will listen on all interfaces on the host. If a host has multiple network interfaces this may be undesirable as it could expose swarm services to networks which are not involved with the operation of the swarm.

    By passing a specific IP address to the `--listen-addr`, a specific network interface can be specified, limiting this exposure.
  "
  desc  'rationale', "
    By default, Docker swarm services will listen on all interfaces on the host.  This may not be necessary for the operation of the swarm where the host has multiple network interfaces.

    When a swarm is initialized the default value for the `--listen-addr` flag is `0.0.0.0:2377` which means that swarm services will listen on all interfaces on the host. If a host has multiple network interfaces this may be undesirable as it could expose swarm services to networks which are not involved with the operation of the swarm.

    By passing a specific IP address to the `--listen-addr`, a specific network interface can be specified, limiting this exposure.
  "
  desc  'check', "
    You should check the network listener on port 2377 (the default for docker swarm) and 7946 (container network discovery), and confirm that it is only listening on specific interfaces. For example, in this could be done using the following command:
    ```
    ss -lp | grep -iE ':2377|:7946'
    ```
  "
  desc  'fix', "
    Resolving this issues requires re-initialization of the swarm, specifying a specific interface for the `--listen-addr` parameter.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-7 a']
  tag nist_r4:               ['SC-7 a']
  tag cci:                   ['CCI-001097']
  tag cis_number:            '7.2'
  tag cis_rid:               '7.2'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0702r1_rule'
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
    describe "CIS Docker 7.2 — swarm services bound to specific host interface" do
      skip "not-applicable: AWS Fargate uses ECS scheduling; no Docker Swarm services exist."
    end
  else
    describe 'Requires manual review and attestation' do
    skip "Requires manual review and attestation provided for this control (swarm-service interface binding is consumer-policy-specific (which interface each service uses) — operators attest from their swarm-network architecture)"
  end
  end
end
