# encoding: UTF-8

control 'C-4.5' do
  title 'Ensure Content trust for Docker is Enabled'
  desc  "
    Content trust is disabled by default and should be enabled in line with organizational security policy.

    Content trust provides the ability to use digital signatures for data sent to and received from remote Docker registries. These signatures allow client-side verification of the identity and the publisher of specific image tags and ensures the provenance of container images.
  "
  desc  'rationale', "
    Content trust is disabled by default and should be enabled in line with organizational security policy.

    Content trust provides the ability to use digital signatures for data sent to and received from remote Docker registries. These signatures allow client-side verification of the identity and the publisher of specific image tags and ensures the provenance of container images.
  "
  desc  'check', "
    You should execute the following command:
    ```
    echo $DOCKER_CONTENT_TRUST 
    ```
    This should return a value of 1.
  "
  desc  'fix', "
    To enable content trust in a bash shell, you should enter the following command:
    ```
    export DOCKER_CONTENT_TRUST=1
    ```
    Alternatively, you could set this environment variable in your profile file so that content trust in enabled on every login.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '4.5'
  tag cis_rid:               '4.5'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0405r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag exec_validated:        false

  describe 'Requires manual review and attestation' do
    skip "Requires manual review and attestation provided for this control (Docker Content Trust (DCT) is a build-host-side environment variable (DOCKER_CONTENT_TRUST=1) — not visible from a running container; operators attest from their image-build pipeline configuration)"
  end
end
