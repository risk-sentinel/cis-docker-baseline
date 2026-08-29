# encoding: UTF-8

control 'C-5.2' do
  title 'Ensure that, if applicable, an AppArmor Profile is enabled'
  desc  "
    AppArmor is an effective and easy-to-use Linux application security system. It is available on some Linux distributions by default, for example, on Debian and Ubuntu.

    AppArmor protects the Linux OS and applications from various threats by enforcing a security policy which is also known as an AppArmor profile. You can create your own AppArmor profile for containers or use Docker's default profile. Enabling this feature enforces security policies on containers as defined in the profile.
  "
  desc  'rationale', "
    AppArmor is an effective and easy-to-use Linux application security system. It is available on some Linux distributions by default, for example, on Debian and Ubuntu.

    AppArmor protects the Linux OS and applications from various threats by enforcing a security policy which is also known as an AppArmor profile. You can create your own AppArmor profile for containers or use Docker's default profile. Enabling this feature enforces security policies on containers as defined in the profile.
  "
  desc  'check', "
    You should run the command below:
    ```
    docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: AppArmorProfile={{ .AppArmorProfile }}'
    ```
    This command should return a valid AppArmor Profile for each container instance.
  "
  desc  'fix', "
    If AppArmor is applicable for your Linux OS, you should enable it.

    1. Verify AppArmor is installed.
    2. Create or import a AppArmor profile for Docker containers.
    3. Enable enforcement of the policy.
    4. Start your Docker container using the customized AppArmor profile. For example:

    ```
    docker run --interactive --tty --security-opt=\"apparmor:PROFILENAME\" ubuntu /bin/bash
    ```

    Alternatively, Docker's default AppArmor policy can be used.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['IA-5 (1) (e)', 'SI-16']
  tag nist_r4:               ['IA-5 (1) (e)', 'SI-16']
  tag cci:                   ['CCI-000200', 'CCI-002823']
  tag cis_number:            '5.2'
  tag cis_rid:               '5.2'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0502r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  describe file('/proc/self/attr/current') do
    its('content') { should_not match(/unconfined/i) }
  end
end
