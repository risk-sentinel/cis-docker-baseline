# encoding: UTF-8

control 'C-4.8' do
  title 'Ensure setuid and setgid permissions are removed'
  desc  "
    Removing setuid and setgid permissions in the images can prevent privilege escalation attacks within containers.

    setuid and setgid permissions can be used for privilege escalation. Whilst these permissions can on occasion be legitimately needed, you should consider removing them from packages which do not need them.  This should be reviewed for each image.
  "
  desc  'rationale', "
    Removing setuid and setgid permissions in the images can prevent privilege escalation attacks within containers.

    setuid and setgid permissions can be used for privilege escalation. Whilst these permissions can on occasion be legitimately needed, you should consider removing them from packages which do not need them.  This should be reviewed for each image.
  "
  desc  'check', "
    You should run the command below against each image to list the executables which have either setuid or setgid permissions:

    ```
    docker export | tar -tv 2>/dev/null | grep -E '^[-rwx].*(s|S).*\\s[0-9]'
    ```

    You should then review the list and ensure that all executables configured with these permissions actually require them.
  "
  desc  'fix', "
    You should allow setuid and setgid permissions only on executables which require them. You could remove these permissions at build time by adding the following command in your Dockerfile, preferably towards the end of the Dockerfile:

    ```
    RUN find / -perm /6000 -type f -exec chmod a-s {} \\; || true 
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 c']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-IAM-SUS']
  tag nist_r4:               ['AC-2 c']
  tag cci:                   ['CCI-002113']
  tag cis_number:            '4.8'
  tag cis_rid:               '4.8'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0408r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  # Allowlist of legitimate setuid/setgid binaries common in many base images.
  expected_setuid = %w[
    /usr/bin/su /usr/bin/sudo /usr/bin/passwd /usr/bin/chsh /usr/bin/chfn
    /usr/bin/gpasswd /usr/bin/newgrp /usr/bin/mount /usr/bin/umount
    /usr/bin/ping /usr/bin/ping6
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    /usr/lib/openssh/ssh-keysign
    /usr/lib/policykit-1/polkit-agent-helper-1
    /bin/su /bin/mount /bin/umount /bin/ping /bin/ping6
  ]
  setuid_output = command('find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null').stdout.to_s
  found = setuid_output.lines.map(&:strip).reject(&:empty?)
  unexpected = found.reject { |p| expected_setuid.include?(p) }

  describe 'container filesystem setuid/setgid binaries outside the common-base-image allowlist' do
    subject { unexpected }
    it { should be_empty }
  end
end
