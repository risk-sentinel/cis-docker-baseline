# encoding: UTF-8

control 'C-4.1' do
  title 'Ensure that a user for the container has been created'
  desc  "
    Containers should run as a non-root user.

    It is good practice to run the container as a non-root user, where possible.  This can be done either via the `USER` directive in the `Dockerfile` or through `gosu` or similar where used as part of the `CMD` or `ENTRYPOINT` directives.
  "
  desc  'rationale', "
    Containers should run as a non-root user.

    It is good practice to run the container as a non-root user, where possible.  This can be done either via the `USER` directive in the `Dockerfile` or through `gosu` or similar where used as part of the `CMD` or `ENTRYPOINT` directives.
  "
  desc  'check', "
    You should run the following command

    ```
    docker ps --quiet | xargs --max-args=1 -I{} docker exec {} cat /proc/1/status | grep '^Uid:' | awk '{print $3}'
    ```
    This should return the effective UID for each container and where it returns 0, it indicates that the container process is running as root.

    Note that some services may start as the root user and then starts all other related processes as an unprivileged user.
  "
  desc  'fix', "
    You should ensure that the Dockerfile for each container image contains the information below:
    ```
    USER ```
    In this case, the user name or ID refers to the user that was found in the container base image. If there is no specific user created in the container base image, then make use of the `useradd` command to add a specific user before the `USER` instruction in the Dockerfile.

    For example, add the below lines in the Dockerfile to create a user in the container:
    ```
    RUN useradd -d /home/username -m -s /bin/bash username
    USER username 
    ```
    Note: If there are users in the image that are not needed,  you should consider deleting them. After deleting those users, commit the image and then generate new instances of the containers.

    Alternatively, if it is not possible to set the `USER` directive in the Dockerfile, a script running as part of the `CMD` or `ENTRYPOINT` sections of the Dockerfile should be used to ensure that the container process switches to a non-root user.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '4.1'
  tag cis_rid:               '4.1'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0401r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  allowlist = Array(input('docker_image_user_allowlist'))
  uid_output = command('id -u').stdout.to_s.strip
  uname_output = command('id -un').stdout.to_s.strip

  if allowlist.empty?
    describe "container effective user — must not be root (uid=#{uid_output.inspect}, name=#{uname_output.inspect})" do
      subject { uid_output }
      it { should_not eq '0' }
    end
  else
    describe "container effective user — must be in docker_image_user_allowlist (uid=#{uid_output.inspect}, name=#{uname_output.inspect})" do
      subject { [uid_output, uname_output] }
      it { should satisfy { |pair| allowlist.include?(pair[0]) || allowlist.include?(pair[1]) } }
    end
  end
end
