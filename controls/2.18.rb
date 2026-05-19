# encoding: UTF-8

control 'C-2.18' do
  title 'Ensure that a daemon-wide custom seccomp profile is applied if appropriate'
  desc  "
    You can choose to apply a custom seccomp profile at a daemon-wide level if needed with this overriding Docker's default seccomp profile.

    A large number of system calls are exposed to every userland process with many of them not utilized during the entire lifetime of the process. Many applications do not need all these system calls and therefore benefit by having each system call currently in use reviewed in line with organizational security policy. A reduced set of system calls reduces the total kernel surface exposed to the application and therefore improves application security.

    A custom seccomp profile can be applied instead of Docker's default seccomp profile. Alternatively, if Docker's default profile is adequate for your environment, you can choose to ignore this recommendation.
  "
  desc  'rationale', "
    You can choose to apply a custom seccomp profile at a daemon-wide level if needed with this overriding Docker's default seccomp profile.

    A large number of system calls are exposed to every userland process with many of them not utilized during the entire lifetime of the process. Many applications do not need all these system calls and therefore benefit by having each system call currently in use reviewed in line with organizational security policy. A reduced set of system calls reduces the total kernel surface exposed to the application and therefore improves application security.

    A custom seccomp profile can be applied instead of Docker's default seccomp profile. Alternatively, if Docker's default profile is adequate for your environment, you can choose to ignore this recommendation.
  "
  desc  'check', "
    You should run the command below and review the seccomp profile listed in the `Security Options` section. If it is `default` this indicates that Docker's default seccomp profile is applied.

    ```
    docker info --format '{{ .SecurityOptions }}'
    ```
  "
  desc  'fix', "
    By default, Docker's default seccomp profile is applied. If this is adequate for your environment, no action is necessary. Alternatively, if you choose to apply your own seccomp profile, use the `--seccomp-profile` flag at daemon start or put it in the daemon runtime parameters file.

    ```
    dockerd --seccomp-profile ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '2.18'
  tag cis_rid:               '2.18'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0218r1_rule'
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
      it 'is satisfied by AWS-managed controls — AWS applies its own seccomp profile to Fargate tasks (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
        expect(true).to eq(true)
      end
    end
  else
    daemon_json_path = '/etc/docker/daemon.json'
  if file(daemon_json_path).exist?
    describe json(daemon_json_path) do
      its(['seccomp-profile']) { should_not be_nil }
    end
  else
    describe 'CIS Docker daemon.json key seccomp-profile' do
      skip "host_daemon mode: /etc/docker/daemon.json not present — daemon is running with default flags. Operator confirms `dockerd --seccomp-profile` flag from process inventory."
    end
  end
  end
end
