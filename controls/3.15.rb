# encoding: UTF-8

control 'C-3.15' do
  title 'Ensure that the Docker socket file ownership is set to root:docker'
  desc  "
    You should verify that the Docker socket file is owned by `root` and group owned by `docker`.

    The Docker daemon runs as `root`. The default Unix socket therefore must be owned by `root`. If any other user or process owns this socket, it might be possible for that non-privileged user or process to interact with the Docker daemon. Additionally, in this case a non-privileged user or process might be able to  interact with containers which is neither a secure nor desired behavior.

    Additionally, the Docker installer creates a Unix group called `docker`. You can add users to this group, and in this case, those users would be able to read and write to the default Docker Unix socket. The membership of the `docker` group is tightly controlled by the system administrator. However, ff any other group owns this socket, then it might be possible for members of that group to interact with the Docker daemon. Such a group might not be as tightly controlled as the `docker` group. Again, this is not in line with good security practice.

    For these reason, the default Docker Unix socket file should be owned by `root` and group owned by `docker` to maintain the integrity of the socket file.
  "
  desc  'rationale', "
    You should verify that the Docker socket file is owned by `root` and group owned by `docker`.

    The Docker daemon runs as `root`. The default Unix socket therefore must be owned by `root`. If any other user or process owns this socket, it might be possible for that non-privileged user or process to interact with the Docker daemon. Additionally, in this case a non-privileged user or process might be able to  interact with containers which is neither a secure nor desired behavior.

    Additionally, the Docker installer creates a Unix group called `docker`. You can add users to this group, and in this case, those users would be able to read and write to the default Docker Unix socket. The membership of the `docker` group is tightly controlled by the system administrator. However, ff any other group owns this socket, then it might be possible for members of that group to interact with the Docker daemon. Such a group might not be as tightly controlled as the `docker` group. Again, this is not in line with good security practice.

    For these reason, the default Docker Unix socket file should be owned by `root` and group owned by `docker` to maintain the integrity of the socket file.
  "
  desc  'check', "
    You should execute the below command to verify that the Docker socket file is owned by `root` and group owned by `docker`:
    ```
    stat -c %U:%G /var/run/docker.sock | grep -v root:docker
    ```
    The command above should return no results.
  "
  desc  'fix', "
    You should execute the following command:
    ```
    chown root:docker /var/run/docker.sock
    ```
    This sets the ownership to `root` and group ownership to `docker` for the default Docker socket file.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3']
  tag cci:                   ['CCI-000213']
  tag cis_number:            '3.15'
  tag cis_rid:               '3.15'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0315r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  if input('docker_target_mode') == 'container_only'
    tag implementation_status:  'inherited'
    tag inherited_from:         'aws-shared-responsibility'
    tag attestation_references: ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  else
    tag implementation_status:  'implemented'
  end
  tag exec_validated:           false

  if input('docker_target_mode') == 'container_only'
    describe 'AWS shared-responsibility inheritance' do
      it 'is satisfied by AWS-managed controls — AWS doesn\'t expose docker.sock on Fargate (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
        expect(true).to eq(true)
      end
    end
  else
    describe file('/var/run/docker.sock') do
    it { should exist }
    it { should be_owned_by 'root' }
    its('group') { should eq 'docker' }
  end
  end
end
