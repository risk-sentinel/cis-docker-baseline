# encoding: UTF-8

control 'C-4.10' do
  title 'Ensure secrets are not stored in Dockerfiles'
  desc  "
    Do not store any secrets in Dockerfiles.

    Docker images are not opaque and contain information about the commands used to build them.  As such secrets should not be included in Dockerfiles used to build images as they will be visible to any users of the image.
  "
  desc  'rationale', "
    Do not store any secrets in Dockerfiles.

    Docker images are not opaque and contain information about the commands used to build them.  As such secrets should not be included in Dockerfiles used to build images as they will be visible to any users of the image.
  "
  desc  'check', "
    Run the below command to get the list of images:
    ```
    docker images
    ```

    Run the below command for each image in the list above, and look for any secrets:
    ```
    docker history ```
    Alternatively, if you have access to Dockerfile for the image, verify that there are no secrets as described above.
  "
  desc  'fix', "
    Do not store any kind of secrets within Dockerfiles. Where secrets are required during the build process, make use of a secrets management tool, such as the buildkit builder included with Docker.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '4.10'
  tag cis_rid:               '4.10'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0410r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  uri = input('c_4_10_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-4.10') if uri.to_s.empty?
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (secrets in Dockerfiles is a build-time concern detected by image-scanning tooling (truffleHog, gitleaks, ECR scan); operators attest from their pipeline scan results) [Lift: set boundary_docs_base / c_4_10_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: input('attestation_max_age_days', value: 365))
    describe "Boundary policy attestation (C-4.10) (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current") { expect(doc.current?).to eq(true) }
    end
  end
end
