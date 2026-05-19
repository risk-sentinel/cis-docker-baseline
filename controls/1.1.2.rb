# encoding: UTF-8

control 'C-1.1.2' do
  title 'Ensure only trusted users are allowed to control Docker daemon'
  desc  "
    The Docker daemon currently requires access to the Docker socket which is, by default, owned by the user `root` and the group `docker`.

    Docker allows you to share a directory between the Docker host and a guest container without limiting the access rights of the container. This means that you can start a container and map the `/` directory on your host to the container. The container would then be able to modify your host file system without any restrictions. This means that you could gain elevated privileges simply by being a member of the `docker` group and subsequently start a container which maps the root `/` directory on the host.
  "
  desc  'rationale', "
    The Docker daemon currently requires access to the Docker socket which is, by default, owned by the user `root` and the group `docker`.

    Docker allows you to share a directory between the Docker host and a guest container without limiting the access rights of the container. This means that you can start a container and map the `/` directory on your host to the container. The container would then be able to modify your host file system without any restrictions. This means that you could gain elevated privileges simply by being a member of the `docker` group and subsequently start a container which maps the root `/` directory on the host.
  "
  desc  'check', "
    Execute the following command on the docker host and ensure that only trusted users are members of the `docker` group.
    ```
    getent group docker
    ```
  "
  desc  'fix', "
    You should remove any untrusted users from the `docker` group. Additionally, you should not create a mapping of sensitive directories from the host to container volumes.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-2 i 1']
  tag cci:                   ['CCI-002126']
  tag cis_number:            '1.1.2'
  tag cis_rid:               '1.1.2'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-010102r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  if input('docker_target_mode') == 'container_only'
    tag implementation_status:  'inherited'
    tag inherited_from:         'aws-shared-responsibility'
    tag attestation_references: ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  else
    tag implementation_status:  'alternative'
  end
  tag exec_validated:           false

  if input('docker_target_mode') == 'container_only'
    describe 'AWS shared-responsibility inheritance' do
      it 'is satisfied by AWS-managed controls — AWS controls who has dockerd-equivalent access on Fargate hosts (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
        expect(true).to eq(true)
      end
    end
  else
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (the set of \"trusted users\" allowed in the docker group is consumer-policy-specific; operators attest the docker-group membership against their access policy)"
    end
  end
end
