# encoding: UTF-8

control 'C-4.7' do
  title 'Ensure update instructions are not used alone in Dockerfiles'
  desc  "
    You should not use OS package manager update instructions such as `apt-get update` or `yum update` either alone or in a single line in any Dockerfiles used to generate images under review.

    Adding update instructions in a single line on the Dockerfile will cause the update layer to be cached. When you then build any image later using the same instruction, this will cause the previously cached update layer to be used, potentially preventing any fresh updates from being applied to later builds.
  "
  desc  'rationale', "
    You should not use OS package manager update instructions such as `apt-get update` or `yum update` either alone or in a single line in any Dockerfiles used to generate images under review.

    Adding update instructions in a single line on the Dockerfile will cause the update layer to be cached. When you then build any image later using the same instruction, this will cause the previously cached update layer to be used, potentially preventing any fresh updates from being applied to later builds.
  "
  desc  'check', "
    Step 1: Run the command below to get the list of images:
    ```
    docker images 
    ```
    Step 2: Run the command below against each image in the list above, looking for any update instructions which are incorporated in a single line:
    ```
    docker history ```
    Alternatively, if you have access to the Dockerfile for the image, you should verify that there are no update instructions configured as described above.
  "
  desc  'fix', "
    You should use update instructions together with install instructions and version pinning for packages while installing them. This will prevent caching and force the extraction of the required versions.

    Alternatively, you could use the `--no-cache` flag during the `docker build` process to avoid using cached layers.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['IA-5 (1) (e)', 'CM-6 a']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-IAM-APM', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 a', 'IA-5 (1) (e)']
  tag cci:                   ['CCI-000200', 'CCI-000363']
  tag cis_number:            '4.7'
  tag cis_rid:               '4.7'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0407r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  uri = input('c_4_7_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-4.7') if uri.to_s.empty?
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (Dockerfile RUN-instruction layering (no standalone `apt-get update`) is a build-time concern not visible from a running container; operators attest from Dockerfile review) [Lift: set boundary_docs_base / c_4_7_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: input('attestation_max_age_days', value: 365))
    describe "Boundary policy attestation (C-4.7) (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current") { expect(doc.current?).to eq(true) }
    end
  end
end
