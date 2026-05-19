# encoding: UTF-8

control 'C-4.3' do
  title 'Ensure that unnecessary packages are not installed in the container'
  desc  "
    Containers should have as small a footprint as possible, and should not contain unnecessary software packages which could increase their attack surface.

    Unnecessary software should not be installed into containers, as doing so increases their attack surface.  Only packages strictly necessary for the correct operation of the application being deployed should be installed.
  "
  desc  'rationale', "
    Containers should have as small a footprint as possible, and should not contain unnecessary software packages which could increase their attack surface.

    Unnecessary software should not be installed into containers, as doing so increases their attack surface.  Only packages strictly necessary for the correct operation of the application being deployed should be installed.
  "
  desc  'check', "
    List all the running instances of containers by executing the command below:
    ```
    docker ps --quiet
    ```

    For each container instance, execute the relevant command for listing all installed packages, e.g.:
    ```
    docker exec $INSTANCE_ID rpm -qa
    ```

    The command above lists the packages installed. You should review the list and ensure that everything installed is actually required.
  "
  desc  'fix', "
    You should not install anything within the container that is not required. 

    You should consider using a minimal base image rather than the standard Centos, Debian, or Red Hat images if you can. Some of the options available include BusyBox and Alpine.

    Not only can this trim your image size considerably, but there would also be fewer pieces of software which could contain vectors for attack.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'IA-5 (1) (e)']
  tag cci:                   ['CCI-000381', 'CCI-000200']
  tag cis_number:            '4.3'
  tag cis_rid:               '4.3'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0403r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag exec_validated:        false

  describe 'Requires manual review and attestation' do
    skip "Requires manual review and attestation provided for this control (\"unnecessary packages\" is consumer-policy-specific (per-image baseline) — operators attest from their image-build manifest / Dockerfile review)"
  end
end
