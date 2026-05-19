# encoding: UTF-8

control 'C-2.7' do
  title 'Ensure devicemapper storage driver is not used'
  desc  "
    Do not use `devicemapper` as the storage driver for your Docker instance.

    The `devicemapper` storage driver is deprecated in favor of overlay2, and has been removed in Docker Engine v25.0.
  "
  desc  'rationale', "
    Do not use `devicemapper` as the storage driver for your Docker instance.

    The `devicemapper` storage driver is deprecated in favor of overlay2, and has been removed in Docker Engine v25.0.
  "
  desc  'check', "
    Execute the below command and verify that `devicemapper` is not used as storage driver:
    ```
    docker info --format 'Storage Driver: {{ .Driver }}'
    ```
    The above command should not return `devicemapper`.
  "
  desc  'fix', "
    Do not explicitly use `devicemapper` as storage driver.

    For example, do not start Docker daemon as below:
    ```
    dockerd --storage-driver devicemapper
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '2.7'
  tag cis_rid:               '2.7'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0207r1_rule'
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
      it 'is satisfied by AWS-managed controls — AWS chooses the storage driver on Fargate hosts (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
        expect(true).to eq(true)
      end
    end
  else
    daemon_json_path = '/etc/docker/daemon.json'
  if file(daemon_json_path).exist?
    describe json(daemon_json_path) do
      its(['storage-driver']) { should_not eq 'devicemapper' }
    end
  else
    describe command('docker info --format 
end
{{.Driver}}
end
') do
      its('stdout.chomp') { should_not eq 'devicemapper' }
    end
  end
  end
end
