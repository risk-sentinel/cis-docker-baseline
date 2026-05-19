# encoding: UTF-8

control 'C-4.11' do
  title 'Ensure only verified packages are installed'
  desc  "
    You should verify the authenticity of packages before installing them into images.

    Verifying authenticity of software packages is essential for building a secure container image. Packages with no known provenance could potentially be malicious or have vulnerabilities that could be exploited.
  "
  desc  'rationale', "
    You should verify the authenticity of packages before installing them into images.

    Verifying authenticity of software packages is essential for building a secure container image. Packages with no known provenance could potentially be malicious or have vulnerabilities that could be exploited.
  "
  desc  'check', "
    Run the command below to get the list of images:
    ```
    docker images 
    ```

    Run the command below for each image in the list above, and check how the authenticity of the packages is being determined. This could be via the use of GPG keys or other secure package distribution mechanisms.

    ```
    docker history ```
    Alternatively, if you have access to Dockerfile for the image, verify that the authenticity of the packages is checked.
  "
  desc  'fix', "
    You should use a secure package distribution mechanism of your choice to ensure the authenticity of software packages.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['MA-3 a', 'CA-5 a']
  tag cci:                   ['CCI-000865', 'CCI-000264']
  tag cis_number:            '4.11'
  tag cis_rid:               '4.11'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0411r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag exec_validated:        false

  describe 'Requires manual review and attestation' do
    skip "Requires manual review and attestation provided for this control (package-signing-verification is a build-time concern enforced by package-manager flags / lockfiles (apt-get with signed lists, dnf gpgcheck, npm audit signatures); operators attest from their build pipeline)"
  end
end
