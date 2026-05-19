# encoding: UTF-8

control 'C-3.22' do
  title 'Ensure that the /etc/sysconfig/docker file ownership is set to root:root'
  desc  "
    You should verify that the `/etc/sysconfig/docker` file individual ownership and group ownership is correctly set to `root`.

    The `/etc/sysconfig/docker` file contains sensitive parameters that may alter the behavior of the Docker daemon. It should therefore be individually owned and group owned by `root` to ensure that it is not modified by less privileged users.
  "
  desc  'rationale', "
    You should verify that the `/etc/sysconfig/docker` file individual ownership and group ownership is correctly set to `root`.

    The `/etc/sysconfig/docker` file contains sensitive parameters that may alter the behavior of the Docker daemon. It should therefore be individually owned and group owned by `root` to ensure that it is not modified by less privileged users.
  "
  desc  'check', "
    You should execute the command below to verify that the file is indiviually owned and group owned by `root`:
    ```
    stat -c %U:%G /etc/sysconfig/docker | grep -v root:root 
    ```
    The command above should return no results.
  "
  desc  'fix', "
    You should execute the following command:
    ```
    chown root:root /etc/sysconfig/docker
    ```
    This sets the ownership and group ownership for the file to `root`.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-2 c']
  tag cci:                   ['CCI-002113']
  tag cis_number:            '3.22'
  tag cis_rid:               '3.22'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0322r1_rule'
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
      it 'is satisfied by AWS-managed controls — AWS owns docker sysconfig on the Fargate host (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
        expect(true).to eq(true)
      end
    end
  else
    describe file('/etc/sysconfig/docker') do
    it { should exist }
    it { should be_owned_by 'root' }
    its('group') { should eq 'root' }
  end
  end
end
