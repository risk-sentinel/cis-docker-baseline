# encoding: UTF-8

control 'C-4.2' do
  title 'Ensure that containers use only trusted base images'
  desc  "
    You should ensure that container images you use are either written from scratch or are based on another established and trusted base image downloaded over a secure channel.

    Official repositories contain Docker images curated and optimized by the Docker community or by their vendor. There is no guarantee that these images are safe and do not contain security vulnerabilities or malicious code. Caution should therefore be exercised when obtaining container images from Docker and third parties and running these images should be reviewed in line with organizational security policy.
  "
  desc  'rationale', "
    You should ensure that container images you use are either written from scratch or are based on another established and trusted base image downloaded over a secure channel.

    Official repositories contain Docker images curated and optimized by the Docker community or by their vendor. There is no guarantee that these images are safe and do not contain security vulnerabilities or malicious code. Caution should therefore be exercised when obtaining container images from Docker and third parties and running these images should be reviewed in line with organizational security policy.
  "
  desc  'check', "
    You should review what Docker images are present on the host by executing the command below:

    ```
    docker images
    ```

    This command lists all the container images that are currently available for use on the Docker host. You should then review the origin of each image and review its contents in line with your organization's security policy.

    You can use the command below to review the history of commits to the image.
    ```
    docker history ```
  "
  desc  'fix', "
    The following procedures are useful for establishing trust for a specific image.

    - Configure and use Docker Content trust.
    - View the history of each Docker image to evaluate its risk, dependent on the sensitivity of the application   you wish to deploy using it.
    - Scan Docker images for vulnerabilities at regular intervals.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['IA-5 (1) (e)', 'CM-6 a']
  tag cci:                   ['CCI-000200', 'CCI-000363']
  tag cis_number:            '4.2'
  tag cis_rid:               '4.2'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0402r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  registries = Array(input('docker_authorized_registries'))
  if registries.empty?
    # No registry allowlist configured -> fall back to a boundary image-provenance
    # attestation. Empty -> Skip (preserves the prior rationale
    # + saf attest apply fallback).
    uri = input('c_4_2_attestation_uri', value: '')
    uri = attestation_uri(:boundary, 'C-4.2') if uri.to_s.empty?
    if uri.to_s.empty?
      describe 'CIS Docker 4.2 — only trusted base images' do
        skip 'Requires manual review and attestation provided for this control (set `docker_authorized_registries` to trusted registry URI prefixes for automated enforcement, set boundary_docs_base / c_4_2_attestation_uri to the image-provenance policy, or `saf attest apply`.)'
      end
    else
      doc = document_attestation(uri, max_age_days: input('attestation_max_age_days', value: 365))
      describe "CIS Docker 4.2 image-provenance attestation (#{uri})" do
        it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
        it('exists') { expect(doc.exists?).to eq(true) }
        it("current") { expect(doc.current?).to eq(true) }
      end
    end
  else
    image_ref = command('cat /proc/1/cgroup').stdout.to_s
    describe 'container image-pull source — needs docker-daemon access to assert from a running container' do
      skip 'pending-resource: image registry of a running container is not visible from inside the container without docker-daemon access. host_daemon scans should iterate `docker ps` + `docker inspect` and assert image-prefix membership; tracked as future work.'
    end
  end
end
