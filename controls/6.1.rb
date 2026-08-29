# encoding: UTF-8

control 'C-6.1' do
  title 'Ensure that image sprawl is avoided'
  desc  "
    You should not keep a large number of container images on the same host. Use only tagged images as appropriate.

    Tagged images are useful if you need to fall back from the \"latest\" version to a specific version of an image in production. Images with unused or old tags may contain vulnerabilities that might be exploited if instantiated.
  "
  desc  'rationale', "
    You should not keep a large number of container images on the same host. Use only tagged images as appropriate.

    Tagged images are useful if you need to fall back from the \"latest\" version to a specific version of an image in production. Images with unused or old tags may contain vulnerabilities that might be exploited if instantiated.
  "
  desc  'check', "
    Step 1 Make a list of all image IDs that are currently instantiated by executing the command below:

    ```
    docker images --quiet | xargs docker inspect --format '{{ .Id }}: Image={{ .Config.Image }}'
    ```

    Step 2: List all the images present on the system by executing the command below:

    ```
    docker images
    ```

    Step 3: Compare the list of image IDs from Step 1 and Step 2 and look for images that are currently not in use. If any unused or old images are found, discuss with the system administrator the need to keep such images on the system. If images are no longer needed they should be deleted.
  "
  desc  'fix', "
    You should keep only the images that you actually need and establish a workflow to remove old or stale images from the host. Additionally, you should use features such as pull-by-digest to get specific images from the registry.

    You can follow the steps below to find unused images on the system so they can be deleted.

    Step 1 Make a list of all image IDs that are currently instantiated by executing the command below:

    ```
    docker images --quiet | xargs docker inspect --format '{{ .Id }}: Image={{ .Config.Image }}'
    ```

    Step 2: List all the images present on the system by executing the command below:
    ```
    docker images
    ```

    Step 3: Compare the list of image IDs created from Step 1 and Step 2 to find out images which are currently not being instantiated.


    Step 4: Decide if you want to keep the images that are not currently in use. If they are not needed, delete them by executing the following command:
    ```
    docker rmi ```

    Alternatively, the `docker system prune` command can be used to remove dangling images which are not tagged or, if necessary, all images that are not currently used by a running container when used with the `-a` option.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'SA-8']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-IAM-SUS', 'KSI-PIY-RSD']
  tag nist_r4:               ['AC-2 f', 'SA-8']
  tag cci:                   ['CCI-000011', 'CCI-000664']
  tag cis_number:            '6.1'
  tag cis_rid:               '6.1'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0601r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  uri = input('c_6_1_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-6.1') if uri.to_s.empty?
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (image sprawl avoidance is an operational hygiene control (regular `docker image prune`, ECR lifecycle policies, etc.) — operators attest from their image-cleanup process) [Lift: set boundary_docs_base / c_6_1_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: input('attestation_max_age_days', value: 365))
    describe "Boundary policy attestation (C-6.1) (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current") { expect(doc.current?).to eq(true) }
    end
  end
end
