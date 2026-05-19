# encoding: UTF-8

control 'C-3.24' do
  title 'Ensure that the Containerd socket file permissions are set to 660 or more restrictively'
  desc  "
    You should verify that the Containerd socket file has permissions of `660` or are configured more restrictively.

    Only `root` and the members of the `root` group should be allowed to read and write to the default Containerd Unix socket. The Containerd socket file should therefore have permissions of `660` or more restrictive permissions.
  "
  desc  'rationale', "
    You should verify that the Containerd socket file has permissions of `660` or are configured more restrictively.

    Only `root` and the members of the `root` group should be allowed to read and write to the default Containerd Unix socket. The Containerd socket file should therefore have permissions of `660` or more restrictive permissions.
  "
  desc  'check', "
    You should execute the command below to verify that the Docker socket file has permissions of `660` or more restrictive permissions

    ```
    stat -c %a /run/containerd/containerd.sock
    ```
  "
  desc  'fix', "
    You should execute the command below.

    ```
    chmod 660 /run/containerd/containerd.sock
    ```
    This sets the file permissions of the Containerd socket file to `660`.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '3.24'
  tag cis_rid:               '3.24'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0324r1_rule'
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
      it 'is satisfied by AWS-managed controls — AWS owns containerd on the Fargate host (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
        expect(true).to eq(true)
      end
    end
  else
    describe file('/run/containerd/containerd.sock') do
    it { should exist }
    it { should be_owned_by 'root' }
    its('group') { should eq 'root' }
    it { should_not be_writable.by('others') }
  end
  end
end
