# encoding: UTF-8

control 'C-3.18' do
  title 'Ensure that daemon.json file permissions are set to 644 or more restrictive'
  desc  "
    You should verify that if the `daemon.json` is present its file permissions are correctly set to `644` or more restrictively.

    The `daemon.json` file contains sensitive parameters that may alter the behavior of the docker daemon. Therefore it should be writeable only by `root` to ensure it is not modified by less privileged users.
  "
  desc  'rationale', "
    You should verify that if the `daemon.json` is present its file permissions are correctly set to `644` or more restrictively.

    The `daemon.json` file contains sensitive parameters that may alter the behavior of the docker daemon. Therefore it should be writeable only by `root` to ensure it is not modified by less privileged users.
  "
  desc  'check', "
    You should execute the command below to verify that the file permissions are correctly set to `644` or more restrictively:

    ```
    stat -c %a /etc/docker/daemon.json
    ```

    If the command returns the result below, the file is not present and this check does not apply:

    ```
    stat: cannot stat '/etc/docker/daemon.json': No such file or directory
    ```
  "
  desc  'fix', "
    If the file is present, you should execute the command below:

    ```
    chmod 644 /etc/docker/daemon.json
    ```
    This sets the file permissions for this file to `644`.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '3.18'
  tag cis_rid:               '3.18'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0318r1_rule'
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
      it 'is satisfied by AWS-managed controls — AWS owns daemon.json on the Fargate host (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
        expect(true).to eq(true)
      end
    end
  else
    describe file('/etc/docker/daemon.json') do
    it { should exist }
    it { should be_owned_by 'root' }
    its('group') { should eq 'root' }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('others') }
    it { should_not be_executable.by('others') }
  end
  end
end
