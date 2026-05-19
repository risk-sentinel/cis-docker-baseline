# encoding: UTF-8

control 'C-1.1.1' do
  title 'Ensure a separate partition for containers has been created'
  desc  "
    All Docker containers and their data and metadata is stored under `/var/lib/docker` directory. By default, `/var/lib/docker` should be mounted under either the `/` or `/var` partitions dependent on how the Linux operating system in use is configured.

    Docker depends on `/var/lib/docker` as the default directory where all Docker related files, including the images, are stored. This directory could fill up quickly causing both Docker and the host to become unusable. For this reason, you should create a separate partition (logical volume) for storing Docker files.
  "
  desc  'rationale', "
    All Docker containers and their data and metadata is stored under `/var/lib/docker` directory. By default, `/var/lib/docker` should be mounted under either the `/` or `/var` partitions dependent on how the Linux operating system in use is configured.

    Docker depends on `/var/lib/docker` as the default directory where all Docker related files, including the images, are stored. This directory could fill up quickly causing both Docker and the host to become unusable. For this reason, you should create a separate partition (logical volume) for storing Docker files.
  "
  desc  'check', "
    At the Docker host execute one of the below commands:

    ```
    grep '/var/lib/docker\\s' /proc/mounts
    ```

    This should return the partition details for the `/var/lib/docker` mountpoint.

    ```
    mountpoint -- \"$(docker info -f '{{ .DockerRootDir }}')\"
    ```

    This should return whether the configured root directory is a mount point.
  "
  desc  'fix', "
    For new installations,  you should create a separate partition for the `/var/lib/docker` mount point. For systems which have already been installed, you should use the Logical Volume Manager (LVM) within Linux to create a new partition.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '1.1.1'
  tag cis_rid:               '1.1.1'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-010101r1_rule'
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
      it 'is satisfied by AWS-managed controls — AWS Fargate manages host filesystem layout, including any partition isolation for the container-runtime data directory (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
        expect(true).to eq(true)
      end
    end
  else
    describe mount('/var/lib/docker') do
    it { should be_mounted }
  end
  end
end
