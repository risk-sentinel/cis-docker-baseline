# encoding: UTF-8

control 'C-3.2' do
  title 'Ensure that docker.service file permissions are appropriately set'
  desc  "
    You should verify that the `docker.service` file permissions are either set to `644` or to a more restrictive value.

    The `docker.service` file contains sensitive parameters that may alter the behavior of the Docker daemon. It should therefore not be writable by any other user other than `root` in order to ensure that it can not be modified by less privileged users.
  "
  desc  'rationale', "
    You should verify that the `docker.service` file permissions are either set to `644` or to a more restrictive value.

    The `docker.service` file contains sensitive parameters that may alter the behavior of the Docker daemon. It should therefore not be writable by any other user other than `root` in order to ensure that it can not be modified by less privileged users.
  "
  desc  'check', "
    Step 1: Find out the file location:
    ```
    systemctl show -p FragmentPath docker.service
    ```


    Step 2: If the file does not exist, this recommendation is not applicable. If the file exists, execute the command below, including the correct file path in order to verify that the file permissions are set to `644` or a more restrictive value.

    For example:
    ```
    stat -c %a /usr/lib/systemd/system/docker.service
    ```
  "
  desc  'fix', "
    Step 1: Find out the file location:
    ```
    systemctl show -p FragmentPath docker.service
    ```


    Step 2: If the file does not exist, this recommendation is not applicable. If the file exists, execute the command below including the correct file path to set the file permissions to `644`.

    For example,
    ```
    chmod 644 /usr/lib/systemd/system/docker.service
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '3.2'
  tag cis_rid:               '3.2'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0302r1_rule'
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
      it 'is satisfied by AWS-managed controls — AWS owns systemd unit files on the Fargate host (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
        expect(true).to eq(true)
      end
    end
  else
    describe file('/usr/lib/systemd/system/docker.service') do
    it { should exist }
    it { should be_owned_by 'root' }
    its('group') { should eq 'root' }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('others') }
    it { should_not be_executable.by('others') }
  end
  end
end
